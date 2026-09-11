import json

import numpy as np
import pytest

from sih_common import contracts, dga_features as F

ort = pytest.importorskip("onnxruntime")

from sih_detect.dga_model import DgaModel  # noqa: E402
from sih_ml import train_dga  # noqa: E402


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    root = tmp_path_factory.mktemp("models")
    train_dga.train(root, root / "datasets", scale=0.05)
    return root


def test_feature_contract_matches_runtime():
    doc = json.loads((train_dga.REPO / "schemas/features/dga_lexical.v1.json").read_text())
    assert doc["feature_schema_version"] == F.FEATURE_SCHEMA_VERSION
    assert [f["name"] for f in doc["features"]] == F.FEATURE_NAMES
    assert [f["index"] for f in doc["features"]] == list(range(F.DIMENSION))


def test_registrable_and_eligibility():
    assert F.split_registrable("www.example.co.uk")[:2] == ("example.co.uk", "example")
    for q, reason in (("wpad", "not_registrable"), ("plc-1.plant.local", "not_registrable"),
                      ("1.2.0.10.in-addr.arpa", "not_registrable"), ("abc.com", "label_too_short"), (None, "query_unavailable")):
        with pytest.raises(F.NotEligible) as e:
            F.extract(q, F.fit_bigram_table([]))
        assert e.value.reason == reason


def test_bundle_is_valid_and_loadable(bundle):
    dep = json.loads((bundle / "deployment.json").read_text())
    assert contracts.validate("deployment_manifest", dep) == []
    meta = json.loads((bundle / "dga" / dep["models"]["dga"]["version"] / "metadata.json").read_text())
    assert contracts.validate("model_manifest", meta) == []
    assert meta["dataset"]["simulation_only"] is True
    assert meta["calibration"]["confidence_kind"] == "heuristic_score"
    m = DgaModel(str(bundle))
    assert m.load(), m.status_reason
    good, _ = F.extract("www.waterpower.com", m.bigram_table)
    bad, _ = F.extract("xkqzvjwpthrbnmd.biz", m.bigram_table)
    assert m.score(bad)[0] > m.score(good)[0]
    contrib = m.contributions(bad)
    assert len(contrib) == 5 and all(isinstance(c[2], float) for c in contrib)


def test_onnx_matches_numpy_on_golden(bundle):
    dep = json.loads((bundle / "deployment.json").read_text())
    d = bundle / "dga" / dep["models"]["dga"]["version"]
    golden = json.loads((d / "golden.json").read_text())
    sess = ort.InferenceSession(str(d / "model.onnx"), providers=["CPUExecutionProvider"])
    X = np.asarray([g["features"] for g in golden["vectors"]], dtype=np.float32)
    p = sess.run(["p_dga"], {"features": X})[0][:, 0]
    assert np.max(np.abs(p - np.asarray([g["p"] for g in golden["vectors"]]))) <= 1e-6


def test_corrupt_or_missing_model_falls_back(bundle, tmp_path):
    assert not DgaModel(str(tmp_path / "missing")).load()
    import shutil
    copy = tmp_path / "copy"
    shutil.copytree(bundle, copy)
    dep = json.loads((copy / "deployment.json").read_text())
    onnx = copy / "dga" / dep["models"]["dga"]["version"] / "model.onnx"
    onnx.write_bytes(onnx.read_bytes()[:-3] + b"xyz")
    m = DgaModel(str(copy))
    assert not m.load()
    assert "checksum" in m.status_reason
    assert m.score([0.0] * F.DIMENSION) == (None, 0.0)
