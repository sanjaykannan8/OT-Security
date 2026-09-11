"""Deterministic UUIDv5 identifiers. Namespaces and name layouts are frozen in docs/contracts.md."""
from __future__ import annotations

import uuid
from typing import Any

NAMESPACES = {
    "event": uuid.UUID("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a01"),
    "incident": uuid.UUID("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a02"),
    "update": uuid.UUID("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a03"),
    "alert": uuid.UUID("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a04"),
    "feature": uuid.UUID("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a05"),
    "invalid": uuid.UUID("5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a06"),
}


def join_name(*parts: Any) -> str:
    return "|".join("" if p is None else str(p) for p in parts)


def derived_id(namespace: str, *parts: Any) -> str:
    return str(uuid.uuid5(NAMESPACES[namespace], join_name(*parts)))


def event_id(sensor_id: str, boot_id: str, sequence: int, original_sha256: str) -> str:
    return derived_id("event", sensor_id, boot_id, sequence, original_sha256)


def incident_id(threat_class: str, entity_type: str, entity_key: str, incident_epoch_ms: int) -> str:
    return derived_id("incident", threat_class, entity_type, entity_key, incident_epoch_ms)


def update_id(incident: str, update_seq: int) -> str:
    return derived_id("update", incident, update_seq)


def alert_id(detector: str, entity_type: str, entity_key: str, window_end_ms: int, subtype: str) -> str:
    return derived_id("alert", detector, entity_type, entity_key, window_end_ms, subtype)


def feature_record_id(detector: str, entity_type: str, entity_key: str, window_end_ms: int) -> str:
    return derived_id("feature", detector, entity_type, entity_key, window_end_ms)


def invalid_id(stage: str, reason: str, raw_sha256: str | None, sensor_id: str | None,
               boot_id: str | None, sequence: int | None) -> str:
    return derived_id("invalid", stage, reason, raw_sha256, sensor_id, boot_id, sequence)
