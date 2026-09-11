"""Phase 1 gate: strict schemas reject malformed/incompatible records, zero stays distinct from missing,
examples are current, identifiers are reproducible."""
import hashlib
import importlib.util
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator

from sih_common import contracts, ids

ROOT = pathlib.Path(__file__).resolve().parents[2]
EX = ROOT / "schemas" / "examples"
EXPECT = json.loads((EX / "expectations.json").read_text())


def _builder():
    spec = importlib.util.spec_from_file_location("build_examples", EX / "build_examples.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_all_schemas_are_valid_2020_12():
    for kind in contracts.SCHEMA_FILES:
        Draft202012Validator.check_schema(contracts.load_schema(kind))


def test_examples_are_up_to_date():
    files = _builder().build()
    for rel, text in files.items():
        assert (EX / rel).read_text(encoding="utf-8") == text, f"{rel} is stale: run schemas/examples/build_examples.py"


@pytest.mark.parametrize("rel", sorted(EXPECT))
def test_example_validates_as_expected(rel):
    e = EXPECT[rel]
    errs = contracts.validate(e["kind"], json.loads((EX / rel).read_text()))
    if e["valid"]:
        assert errs == []
    else:
        assert errs, "expected rejection"
        assert set(e["codes"]) <= contracts.codes(errs), errs


def test_valid_events_have_reproducible_identity():
    for rel, e in EXPECT.items():
        if e["kind"] != "event" or not e["valid"]:
            continue
        ev = json.loads((EX / rel).read_text())
        if ev["original_record"] is not None:
            assert hashlib.sha256(ev["original_record"].encode()).hexdigest() == ev["original_record_sha256"]
        assert ids.event_id(ev["sensor_id"], ev["sensor_boot_id"], ev["sequence"], ev["original_record_sha256"]) == ev["event_id"]


def test_meaningful_zero_is_distinct_from_missing():
    zero = json.loads((EX / "event/valid/conn_s0_genuine_zero.json").read_text())
    hidden = json.loads((EX / "event/valid/conn_originator_only.json").read_text())
    assert zero["payload"]["resp_bytes"] == 0 and "resp_bytes" not in zero["availability"]
    assert hidden["payload"]["resp_bytes"] is None and hidden["availability"]["resp_bytes"] == "UNKNOWN"
    bad = dict(zero, availability={})
    bad["payload"] = dict(zero["payload"], duration_s=None)
    assert "availability_null" in contracts.codes(contracts.validate("event", bad))


def test_identifier_vectors():
    vec = json.loads((EX / "id_vectors.json").read_text())["vectors"]
    assert len(vec) == 6
    for v in vec:
        assert str(__import__("uuid").uuid5(__import__("uuid").UUID(v["namespace_uuid"]), v["name"])) == v["uuid"]
