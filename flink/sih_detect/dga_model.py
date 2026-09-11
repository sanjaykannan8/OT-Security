"""Local ONNX DGA model: selected by models/deployment.json, verified, warmed, then activated.

Loaded once per operator instance. Any problem (missing bundle, checksum or feature-contract mismatch,
golden-vector disagreement, repeated inference errors) leaves the model inactive: DNS rules keep working
and the reason is exposed through metrics and logs. A checksum proves integrity against the deployment
manifest, not authenticity.
"""
from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import time

from sih_common import dga_features

log = logging.getLogger("sih_detect.dga_model")


def sha256_file(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class DgaModel:
    def __init__(self, model_root: str, disable_after_errors: int = 20):
        self.root = pathlib.Path(model_root)
        self.disable_after = disable_after_errors
        self.active = False
        self.status_reason = "not_loaded"
        self.version = None
        self.threshold = 0.9
        self.calibration_status = "uncalibrated"
        self.confidence_kind = "heuristic_score"
        self.bigram_table = None
        self.meta = None
        self._session = None
        self._consecutive_errors = 0
        self.errors_total = 0
        self.inferences_total = 0

    def load(self) -> bool:
        try:
            self._load()
            self.active = True
            self.status_reason = "active"
            log.info("DGA model %s active (threshold %.3f)", self.version, self.threshold)
        except Exception as e:  # any failure means rules-only mode
            self.active = False
            self.status_reason = str(e)[:200]
            log.warning("DGA model unavailable; DNS detection continues rules-only: %s", e)
        return self.active

    def _load(self) -> None:
        deployment = json.loads((self.root / "deployment.json").read_text(encoding="utf-8"))
        sel = deployment.get("models", {}).get("dga")
        if not sel or not sel.get("enabled"):
            raise RuntimeError("dga model not enabled in deployment manifest")
        d = self.root / "dga" / sel["version"]
        model_path, meta_path = d / "model.onnx", d / "metadata.json"
        if sha256_file(meta_path) != sel["metadata_sha256"]:
            raise RuntimeError("metadata.json checksum does not match deployment manifest")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        digest = sha256_file(model_path)
        if digest != sel["model_sha256"] or digest != meta["model_sha256"]:
            raise RuntimeError("model.onnx checksum does not match manifests")
        fs = meta["feature_schema"]
        if fs["version"] != dga_features.FEATURE_SCHEMA_VERSION or fs["dimension"] != dga_features.DIMENSION:
            raise RuntimeError(f"feature contract {fs['version']}/{fs['dimension']} is not the runtime's "
                               f"{dga_features.FEATURE_SCHEMA_VERSION}/{dga_features.DIMENSION}")
        if sha256_file(d / fs["file"]) != fs["sha256"]:
            raise RuntimeError("feature_schema.json checksum mismatch")
        feature_doc = json.loads((d / fs["file"]).read_text(encoding="utf-8"))
        if [f["name"] for f in feature_doc["features"]] != dga_features.FEATURE_NAMES:
            raise RuntimeError("feature order differs from the runtime contract")
        pre = meta["preprocessing"]
        if sha256_file(d / pre["file"]) != pre["sha256"]:
            raise RuntimeError("preprocessing checksum mismatch")
        self.bigram_table = json.loads((d / pre["file"]).read_text(encoding="utf-8"))["bigram_logprob"]

        import numpy as np
        import onnxruntime as ort
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = meta["runtime"]["intra_op_threads"]
        opts.inter_op_num_threads = meta["runtime"]["inter_op_threads"]
        self._np = np
        self._session = ort.InferenceSession(model_path.read_bytes(), sess_options=opts, providers=["CPUExecutionProvider"])
        self._in = meta["inputs"][0]["name"]
        self._out = meta["outputs"][0]["name"]
        golden = json.loads((d / "golden.json").read_text(encoding="utf-8"))
        for g in golden["vectors"]:
            vec, _ = dga_features.extract(g["query"], self.bigram_table)
            if max(abs(a - b) for a, b in zip(vec, g["features"])) > 1e-9:
                raise RuntimeError(f"runtime features differ from training features for {g['query']!r}")
            p = self._run(vec)
            if abs(p - g["p"]) > 1e-5:
                raise RuntimeError(f"golden score mismatch for {g['query']!r}: {p} vs {g['p']}")
        self.meta = meta
        self.version = meta["model_version"]
        self.threshold = float(meta["decision_threshold"])
        self.calibration_status = meta["calibration"]["status"]
        self.confidence_kind = meta["calibration"]["confidence_kind"]

    def _run(self, vec: list[float]) -> float:
        x = self._np.asarray([vec], dtype=self._np.float32)
        return float(self._session.run([self._out], {self._in: x})[0][0][0])

    def score(self, vec: list[float]) -> tuple[float | None, float]:
        """(probability-like score or None, inference seconds)."""
        if not self.active:
            return None, 0.0
        t0 = time.perf_counter()
        try:
            p = self._run(vec)
            self._consecutive_errors = 0
            self.inferences_total += 1
            return p, time.perf_counter() - t0
        except Exception as e:
            self.errors_total += 1
            self._consecutive_errors += 1
            if self._consecutive_errors >= self.disable_after:
                self.active = False
                self.status_reason = f"disabled after {self._consecutive_errors} consecutive errors: {e}"[:200]
                log.error("DGA model disabled: %s", self.status_reason)
            return None, time.perf_counter() - t0

    def contributions(self, vec: list[float], top: int = 5) -> list[tuple[str, float, float, None]]:
        """Signed contributions to the logit for this vector (exact for the linear model)."""
        ex = self.meta["explanation"]
        items = []
        for name, x, w, mu, sd in zip(dga_features.FEATURE_NAMES, vec, ex["coefficients"], ex["means"], ex["scales"]):
            items.append((name, x, w * (x - mu) / sd, None))
        items.sort(key=lambda t: abs(t[2]), reverse=True)
        return items[:top]
