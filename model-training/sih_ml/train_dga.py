"""Train, export, verify and evaluate the DGA logistic model; write an immutable model bundle.

    python -m sih_ml.train_dga --out /build/models --datasets /build/datasets [--scale 1.0]

Deterministic: fixed seeds, float64 IRLS, no randomness in the solver. The bundle is only written after
ONNX Runtime reproduces the NumPy scores on every golden vector.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import pathlib
import platform
import shutil
import sys

import numpy as np

from sih_common import dga_features as F
from sih_ml import dga_data, onnx_writer

MODEL_VERSION = "dga-lr-1.0.0-sim"
SEED = 20260911
L2 = 1.0
MAX_TARGET_FPR = 0.01
REPO = pathlib.Path(__file__).resolve().parents[2]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def featurize(rows, table):
    X, y, fam, queries, skipped = [], [], [], [], 0
    for q, label, family in rows:
        try:
            vec, _ = F.extract(q, table)
        except F.NotEligible:
            skipped += 1
            continue
        X.append(vec)
        y.append(label)
        fam.append(family)
        queries.append(q)
    return np.asarray(X, dtype=np.float64), np.asarray(y, dtype=np.float64), fam, queries, skipped


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def fit_logistic(Z: np.ndarray, y: np.ndarray, l2: float, max_iter: int = 100) -> tuple[np.ndarray, float, int]:
    """L2-regularized logistic regression by Newton/IRLS on standardized features (bias unregularized)."""
    n, d = Z.shape
    A = np.hstack([Z, np.ones((n, 1))])
    w = np.zeros(d + 1)
    reg = np.full(d + 1, l2)
    reg[-1] = 0.0
    for it in range(1, max_iter + 1):
        p = sigmoid(A @ w)
        g = A.T @ (p - y) + reg * w
        H = (A * (p * (1 - p))[:, None]).T @ A + np.diag(reg) + 1e-9 * np.eye(d + 1)
        step = np.linalg.solve(H, g)
        w -= step
        if np.max(np.abs(step)) < 1e-10:
            break
    return w[:-1], float(w[-1]), it


def roc_auc(y: np.ndarray, s: np.ndarray) -> float:
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s))
    sorted_s = s[order]
    i = 0
    while i < len(s):  # average ranks for ties
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    pos = y == 1
    n_pos, n_neg = pos.sum(), (~pos).sum()
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    return float((ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def average_precision(y: np.ndarray, s: np.ndarray) -> float:
    order = np.argsort(-s, kind="mergesort")
    yt = y[order]
    tp = np.cumsum(yt)
    precision = tp / np.arange(1, len(yt) + 1)
    return float((precision * yt).sum() / max(1, yt.sum()))


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)]


def metrics(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    pred = s >= thr
    tp = int(((y == 1) & pred).sum())
    fp = int(((y == 0) & pred).sum())
    tn = int(((y == 0) & ~pred).sum())
    fn = int(((y == 1) & ~pred).sum())
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    return {
        "samples": int(len(y)), "positives": int((y == 1).sum()), "negatives": int((y == 0).sum()),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": prec, "recall": rec, "recall_ci95": wilson(tp, tp + fn),
        "f1": 2 * prec * rec / (prec + rec) if prec and rec else None,
        "fpr": fp / (fp + tn) if fp + tn else None, "fpr_ci95": wilson(fp, fp + tn),
        "fnr": fn / (fn + tp) if fn + tp else None,
        "roc_auc": roc_auc(y, s) if 0 < (y == 1).sum() < len(y) else None,
        "pr_auc": average_precision(y, s) if (y == 1).sum() else None,
        "brier": float(np.mean((s - y) ** 2)),
    }


def reliability(y: np.ndarray, s: np.ndarray, bins: int = 10) -> list[dict]:
    out = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        m = (s >= lo) & ((s < hi) if b < bins - 1 else (s <= hi))
        if m.any():
            out.append({"bin": [lo, hi], "count": int(m.sum()), "mean_score": float(s[m].mean()), "fraction_dga": float(y[m].mean())})
    return out


def write_csv(path: pathlib.Path, rows) -> tuple[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["query", "label", "family"])
        w.writerows(rows)
    return sha256_bytes(path.read_bytes()), len(rows)


def train(out_root: pathlib.Path, datasets_dir: pathlib.Path, scale: float = 1.0) -> pathlib.Path:
    splits = dga_data.build_datasets(scale)
    files = {}
    for name, rows in splits.items():
        sha, n = write_csv(datasets_dir / f"dga_{name}.csv", rows)
        files[f"dga_{name}.csv"] = {"sha256": sha, "rows": n}

    # Preprocessing learned from benign training names only.
    benign_train_slds = []
    for q, label, _ in splits["train"]:
        if label == 0:
            try:
                benign_train_slds.append(F.split_registrable(F.normalize_name(q))[1])
            except F.NotEligible:
                pass
    table = F.fit_bigram_table(benign_train_slds)

    Xtr, ytr, _, _, skip_tr = featurize(splits["train"], table)
    Xva, yva, _, _, skip_va = featurize(splits["val"], table)
    Xte, yte, fte, qte, skip_te = featurize(splits["test"], table)
    means = Xtr.mean(axis=0)
    scales = Xtr.std(axis=0)
    scales[scales < 1e-9] = 1.0
    coef, intercept, iters = fit_logistic((Xtr - means) / scales, ytr, L2)

    def score(X):
        return sigmoid(((X - means) / scales) @ coef + intercept)

    s_va = score(Xva)
    benign_val = np.sort(s_va[yva == 0])
    thr = float(np.clip(benign_val[int(math.ceil((1 - MAX_TARGET_FPR) * len(benign_val))) - 1], 0.5, 0.99))
    s_te = score(Xte)
    fam = np.asarray(fte)
    per_family = {}
    for family in dga_data.TRAIN_FAMILIES + dga_data.HELDOUT_FAMILIES:
        m = fam == family
        k = int((s_te[m] >= thr).sum())
        per_family[family] = {"samples": int(m.sum()), "recall": k / m.sum() if m.any() else None,
                              "recall_ci95": wilson(k, int(m.sum())),
                              "split": "held_out_family" if family in dga_data.HELDOUT_FAMILIES else "in_family_unseen_seed"}
    in_family = (fam == "benign") | np.isin(fam, dga_data.TRAIN_FAMILIES)
    evaluation = {
        "threshold_selection": f"99th percentile of validation benign scores (target FPR <= {MAX_TARGET_FPR}), clipped to [0.5, 0.99]",
        "validation": metrics(yva, s_va, thr),
        "test_in_family": metrics(yte[in_family], s_te[in_family], thr),
        "test_all_families": metrics(yte, s_te, thr),
        "test_per_family": per_family,
        "reliability_test": reliability(yte, s_te),
        "ineligible_skipped": {"train": skip_tr, "val": skip_va, "test": skip_te},
        "caveat": ("Simulation-trained: synthetic benign vocabulary and generic DGA styles. These numbers measure "
                   "separability of the simulation, not field detection accuracy; dictionary-style DGAs are expected "
                   "to evade lexical features."),
    }

    version_dir = out_root / "dga" / MODEL_VERSION
    if version_dir.exists():
        shutil.rmtree(version_dir)
    version_dir.mkdir(parents=True)

    feature_doc = json.loads((REPO / "schemas" / "features" / "dga_lexical.v1.json").read_text(encoding="utf-8"))
    if [f["name"] for f in feature_doc["features"]] != F.FEATURE_NAMES:
        raise SystemExit("feature contract file and dga_features.FEATURE_NAMES disagree")
    fs_bytes = json.dumps(feature_doc, indent=2).encode("utf-8")
    (version_dir / "feature_schema.json").write_bytes(fs_bytes)
    pre_bytes = json.dumps({"symbols": F.SYMBOLS, "bigram_logprob": table,
                            "fitted_on": "benign training SLD labels only"}).encode("utf-8")
    (version_dir / "preprocessing.json").write_bytes(pre_bytes)

    f32 = lambda a: [float(np.float32(v)) for v in a]  # noqa: E731
    onnx_bytes = onnx_writer.logistic_model(f32(means), f32(scales), f32(coef), float(np.float32(intercept)),
                                            doc=f"{MODEL_VERSION}: simulation-trained DGA lexical logistic regression",
                                            metadata={"model_version": MODEL_VERSION,
                                                      "feature_schema_version": F.FEATURE_SCHEMA_VERSION})
    (version_dir / "model.onnx").write_bytes(onnx_bytes)

    # Golden vectors: verify ONNX Runtime reproduces the float32 NumPy computation.
    import onnxruntime as ort
    sess = ort.InferenceSession(onnx_bytes, providers=["CPUExecutionProvider"])
    golden_idx = list(range(0, len(qte), max(1, len(qte) // 24)))[:24]
    Xg = Xte[golden_idx].astype(np.float32)
    ort_p = sess.run(["p_dga"], {"features": Xg})[0][:, 0]
    m32, s32, c32 = (np.asarray(f32(a), dtype=np.float32) for a in (means, scales, coef))
    np_p = 1 / (1 + np.exp(-(((Xg - m32) / s32) @ c32 + np.float32(intercept))))
    max_diff = float(np.max(np.abs(ort_p - np_p)))
    if max_diff > 1e-5:
        raise SystemExit(f"ONNX Runtime and NumPy disagree on golden vectors (max diff {max_diff})")
    golden = {"tolerance": 1e-5, "max_abs_diff_ort_vs_numpy": max_diff, "onnxruntime": ort.__version__,
              "vectors": [{"query": qte[i], "features": [float(v) for v in Xte[i]], "p": float(p)}
                          for i, p in zip(golden_idx, ort_p)]}
    golden_bytes = json.dumps(golden, indent=1).encode("utf-8")
    (version_dir / "golden.json").write_bytes(golden_bytes)
    (version_dir / "evaluation.json").write_text(json.dumps(evaluation, indent=2), encoding="utf-8")

    metadata = {
        "manifest_schema_version": "1.0.0",
        "threat": "dga",
        "model_version": MODEL_VERSION,
        "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "model_file": "model.onnx",
        "model_sha256": sha256_bytes(onnx_bytes),
        "onnx": {"ir_version": onnx_writer.IR_VERSION, "opset": onnx_writer.OPSET, "producer": "sih_ml.onnx_writer",
                 "exporter": "hand-written protobuf (model-training/sih_ml/onnx_writer.py)"},
        "runtime": {"onnxruntime_verified_versions": [ort.__version__], "intra_op_threads": 1, "inter_op_threads": 1,
                    "execution_provider": "CPUExecutionProvider"},
        "inputs": [{"name": "features", "dtype": "float32", "shape": [-1, F.DIMENSION]}],
        "outputs": [{"name": "p_dga", "dtype": "float32", "shape": [-1, 1],
                     "semantics": "sigmoid of the linear score; higher means more DGA-like in the simulation"}],
        "feature_schema": {"file": "feature_schema.json", "version": F.FEATURE_SCHEMA_VERSION,
                           "sha256": sha256_bytes(fs_bytes), "dimension": F.DIMENSION},
        "preprocessing": {"file": "preprocessing.json", "sha256": sha256_bytes(pre_bytes),
                          "description": "Benign character-bigram log-probability table; standardization is inside the ONNX graph."},
        "required_fields": ["dns.query"],
        "missingness_policy": "abstain",
        "output_semantics": ("Heuristic DGA-likeness score of the registrable label. Not a calibrated probability of "
                             "malicious activity; prevalence in the simulation was balanced."),
        "decision_threshold": round(thr, 6),
        "calibration": {"status": "simulation_only", "method": "none", "version": None, "confidence_kind": "heuristic_score",
                        "notes": "Brier score and reliability bins are reported for the simulation test split only.",
                        "metrics": {"brier_validation": evaluation["validation"]["brier"],
                                    "brier_test_all": evaluation["test_all_families"]["brier"]}},
        "dataset": {"simulation_only": True,
                    "description": "Synthetic benign labels from an embedded vocabulary and generic DGA styles; no external corpus.",
                    "generator": dga_data.GENERATOR_VERSION, "seeds": {"train": 101, "val": 202, "test": 303, "vocabulary": 7},
                    "files": files},
        "split": {"method": ("disjoint seeds per split; benign vocabulary split 60/20/20 so test names use unseen words; "
                             "DGA styles pronounceable/dictionary/base32 held out of training and validation; exact query "
                             "overlap removed")},
        "evaluation": {k: evaluation[k] for k in ("validation", "test_in_family", "test_all_families", "test_per_family")},
        "training": {"python_version": platform.python_version(), "numpy_version": np.__version__,
                     "sklearn_version": "not_used", "seed": SEED,
                     "estimator": "L2-regularized logistic regression, Newton/IRLS (NumPy float64)",
                     "params": {"l2": L2, "iterations": iters, "standardization": "train mean/std"}},
        "explanation": {"type": "linear_contributions", "intercept": float(intercept), "coefficients": [float(c) for c in coef],
                        "means": [float(m) for m in means], "scales": [float(s) for s in scales]},
    }
    meta_bytes = json.dumps(metadata, indent=2).encode("utf-8")
    (version_dir / "metadata.json").write_bytes(meta_bytes)
    sums = "".join(f"{sha256_bytes((version_dir / n).read_bytes())}  {n}\n" for n in
                   ("model.onnx", "metadata.json", "feature_schema.json", "preprocessing.json", "golden.json", "evaluation.json"))
    (version_dir / "checksums.sha256").write_text(sums, encoding="utf-8")
    deployment = {"deployment_manifest_version": "1.0.0",
                  "updated_at": metadata["created_at"],
                  "note": "Only the DGA family has a learned model; the other six threat classes are rules/statistics-only.",
                  "models": {"dga": {"enabled": True, "version": MODEL_VERSION, "model_sha256": metadata["model_sha256"],
                                     "metadata_sha256": sha256_bytes(meta_bytes)}}}
    (out_root / "deployment.json").write_text(json.dumps(deployment, indent=2), encoding="utf-8")
    return version_dir


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--datasets", required=True)
    ap.add_argument("--scale", type=float, default=1.0)
    a = ap.parse_args(argv)
    d = train(pathlib.Path(a.out), pathlib.Path(a.datasets), a.scale)
    ev = json.loads((d / "evaluation.json").read_text())
    summary = {k: {m: ev[k][m] for m in ("precision", "recall", "fpr", "roc_auc", "brier")} for k in
               ("validation", "test_in_family", "test_all_families")}
    print(json.dumps({"bundle": str(d), "summary": summary,
                      "per_family_recall": {f: v["recall"] for f, v in ev["test_per_family"].items()}}, indent=2))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
