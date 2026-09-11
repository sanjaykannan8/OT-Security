"""Reference validation for SIH26145 contracts: JSON Schema plus cross-field rules.

Schema files live in schemas/ (SIH_SCHEMA_DIR overrides). Used by the receiver, consumers, API, fixture
builders and tests; schemas/examples/ holds the shared valid/invalid vectors.
"""
from __future__ import annotations

import json
import os
import pathlib
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker

from sih_common import timeutil


def _schema_dir() -> pathlib.Path:
    env = os.environ.get("SIH_SCHEMA_DIR")
    if env:
        return pathlib.Path(env)
    repo = pathlib.Path(__file__).resolve().parents[2] / "schemas"
    if (repo / "event.v1.schema.json").exists():
        return repo
    return pathlib.Path("/opt/sih/schemas")


SCHEMA_DIR = _schema_dir()

SCHEMA_FILES = {
    "event": "event.v1.schema.json",
    "alert": "alert.v1.schema.json",
    "feature": "feature.v1.schema.json",
    "sensor_health": "sensor-health.v1.schema.json",
    "invalid_event": "invalid-event.v1.schema.json",
    "model_manifest": "model-manifest.v1.schema.json",
    "deployment_manifest": "deployment-manifest.v1.schema.json",
}

VERSION_FIELDS = {
    "event": ("event_schema_version", {"1.0.0"}),
    "alert": ("alert_schema_version", {"1.0.0"}),
    "feature": ("feature_record_schema_version", {"1.0.0"}),
    "sensor_health": ("health_schema_version", {"1.0.0"}),
    "invalid_event": ("invalid_schema_version", {"1.0.0"}),
    "model_manifest": ("manifest_schema_version", {"1.0.0"}),
    "deployment_manifest": ("deployment_manifest_version", {"1.0.0"}),
}

_validators: dict[str, Draft202012Validator] = {}


def load_schema(kind: str) -> dict:
    return json.loads((SCHEMA_DIR / SCHEMA_FILES[kind]).read_text(encoding="utf-8"))


def validator(kind: str) -> Draft202012Validator:
    if kind not in _validators:
        schema = load_schema(kind)
        schema.pop("$id", None)  # resolve "#/$defs" refs against the document itself on every jsonschema version
        Draft202012Validator.check_schema(schema)
        _validators[kind] = Draft202012Validator(schema, format_checker=FormatChecker())
    return _validators[kind]


def _schema_errors(kind: str, obj: Any) -> list[tuple[str, str]]:
    errs = []
    for e in sorted(validator(kind).iter_errors(obj), key=lambda e: [str(p) for p in e.absolute_path]):
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        errs.append(("schema", f"{path}: {e.message[:300]}"))
    return errs


def availability_errors(values: dict, availability: dict, reasons: dict | None) -> list[tuple[str, str]]:
    errs = []
    for key, value in values.items():
        if value is None and key not in availability:
            errs.append(("availability_null", f"{key} is null without an availability state"))
        if value is not None and key in availability:
            errs.append(("availability_on_value", f"{key} has a value but is marked {availability[key]}"))
    for key in availability:
        if key not in values:
            errs.append(("availability_unknown_field", f"availability names unknown field {key}"))
    for key in (reasons or {}):
        if key not in availability:
            errs.append(("reason_without_availability", f"availability_reasons.{key} without availability state"))
    return errs


def _event_rules(ev: dict) -> list[tuple[str, str]]:
    errs = availability_errors(ev["payload"], ev["availability"], ev["availability_reasons"])
    if ev["original_record"] is None and not ev["original_record_truncated"]:
        errs.append(("original_record_null", "original_record is null but original_record_truncated is false"))
    return errs


def _alert_rules(al: dict) -> list[tuple[str, str]]:
    errs = []
    kind = al["confidence_kind"]
    if (al["confidence"] is None) != (kind == "unavailable"):
        errs.append(("confidence_consistency", "confidence must be null exactly when confidence_kind is 'unavailable'"))
    if kind == "calibrated_probability" and al["calibration_status"] != "calibrated":
        errs.append(("calibration_consistency", "calibrated_probability requires calibration_status 'calibrated'"))
    if (al["model_version"] is None) == (al["detection_method"] in ("model", "hybrid")):
        errs.append(("model_version_consistency", "model_version must be set exactly for model/hybrid detections"))
    for a, b in (("window_start", "window_end"), ("first_seen", "last_seen")):
        if timeutil.parse_us(al[a]) > timeutil.parse_us(al[b]):
            errs.append(("time_order", f"{a} is after {b}"))
    return errs


def _feature_rules(fr: dict) -> list[tuple[str, str]]:
    errs = availability_errors(fr["values"], fr["availability"], None)
    for key in fr["capped"]:
        if fr["values"].get(key) is None:
            errs.append(("capped_unknown", f"capped feature {key} has no value"))
    return errs


_CROSS_RULES = {"event": _event_rules, "alert": _alert_rules, "feature": _feature_rules}


def validate(kind: str, obj: Any) -> list[tuple[str, str]]:
    """Return (code, message) pairs; an empty list means valid.

    The version is checked first so an unsupported version is reported as such rather than as a generic
    schema violation.
    """
    field, supported = VERSION_FIELDS[kind]
    if isinstance(obj, dict) and field in obj and obj[field] not in supported:
        return [("unsupported_schema_version", f"{field}={obj[field]!r} not in {sorted(supported)}")]
    errs = _schema_errors(kind, obj)
    if errs:
        return errs
    rule = _CROSS_RULES.get(kind)
    return rule(obj) if rule else []


def is_valid(kind: str, obj: Any) -> bool:
    return not validate(kind, obj)


def observation_ms(ev: dict) -> int:
    """Observation time of an event (docs/contracts.md): event_time + replay offset, plus duration for
    terminal conn records. Used for Kafka record timestamps, storage and detection alike."""
    us = timeutil.parse_us(ev["event_time"]) + int(ev["replay_time_offset_us"])
    if ev["log_type"] == "conn" and ev["payload"].get("duration_s") is not None:
        us += round(float(ev["payload"]["duration_s"]) * 1_000_000)
    return us // 1000


def codes(errors: Iterable[tuple[str, str]]) -> set[str]:
    return {code for code, _ in errors}
