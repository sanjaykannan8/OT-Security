"""Parse raw-events.v1 JSON into the compact dict the detectors use.

The receiver has already validated the full schema; this re-checks only what detection depends on and
quarantines anything else (stage "flink").
"""
from __future__ import annotations

import hashlib
import json

from sih_common import ids, timeutil

SUPPORTED = {"1.0.0"}
LOG_TYPES = {"conn", "flow_update", "dns", "ssl", "weird"}


class Invalid(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def parse(raw: str) -> dict:
    try:
        d = json.loads(raw)
    except (ValueError, RecursionError):
        raise Invalid("json_parse_error", "record is not valid JSON") from None
    if not isinstance(d, dict):
        raise Invalid("json_parse_error", "record is not a JSON object")
    if d.get("event_schema_version") not in SUPPORTED:
        raise Invalid("unsupported_schema_version", f"event_schema_version={d.get('event_schema_version')!r}")
    if d.get("log_type") not in LOG_TYPES:
        raise Invalid("unknown_log_type", f"log_type={d.get('log_type')!r}")
    try:
        et = timeutil.parse_us(d["event_time"])
        recv = timeutil.parse_us(d["receiver_received_at"])
        offset = int(d["replay_time_offset_us"])
        payload = d["payload"]
        avail = d.get("availability") or {}
        if not isinstance(payload, dict) or not isinstance(avail, dict):
            raise ValueError("payload/availability not objects")
        obs_us = et + offset
        if d["log_type"] == "conn" and payload.get("duration_s") is not None:
            obs_us += round(float(payload["duration_s"]) * 1_000_000)
        return {
            "event_id": d["event_id"],
            "sensor_id": d["sensor_id"],
            "boot": d["sensor_boot_id"],
            "run": d.get("replay_run_id"),
            "offset_us": offset,
            "log_type": d["log_type"],
            "event_time_us": et,
            "obs_ms": obs_us // 1000,
            "received_us": recv,
            "coverage": d.get("observation_coverage", "unknown"),
            "p": payload,
            "a": avail,
        }
    except (KeyError, TypeError, ValueError) as e:
        raise Invalid("field_bound_violation", f"missing or invalid field: {str(e)[:200]}") from None


def invalid_record(raw: str, reason: str, detail: str) -> dict:
    data = raw.encode("utf-8", errors="replace")
    sha = hashlib.sha256(data).hexdigest()
    return {
        "invalid_schema_version": "1.0.0",
        "invalid_id": ids.invalid_id("flink", reason, sha, None, None, None),
        "detected_at": timeutil.format_us(timeutil.now_us()),
        "stage": "flink",
        "reason_code": reason,
        "detail": detail[:512],
        "sensor_id": None,
        "sensor_boot_id": None,
        "sequence": None,
        "raw_sha256": sha,
        "raw_size_bytes": len(data),
        "raw_excerpt": raw[:2048],
    }


def flow_key(ev: dict) -> str:
    return f"{ev['sensor_id']}|{ev['boot']}|{ev['run'] or ''}|{ev['p'].get('uid')}"
