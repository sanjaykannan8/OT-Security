"""ClickHouse sinks for raw events, features, alert updates, invalid records and sensor health.

Rows are inserted as JSONEachRow with best-effort ISO timestamp parsing. Tables are ReplacingMergeTree
keyed on deterministic ids, so replayed batches do not create logical duplicates.
"""
from __future__ import annotations

import base64
import json

from sih_common import contracts, env, timeutil
from sih_common.chttp import ClickHouseHTTP
from sih_consumers.base import Poison


def ch_from_env(user_env: str = "CLICKHOUSE_USER", default_user: str = "sih_writer") -> ClickHouseHTTP:
    return ClickHouseHTTP(env.env_str("CLICKHOUSE_URL", "http://clickhouse:8123"), env.env_str(user_env, default_user),
                          env.secret_text("CLICKHOUSE_PASSWORD_FILE"))


def _load(payload: bytes) -> dict:
    try:
        d = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise Poison(f"json_parse_error: {e}") from None
    if not isinstance(d, dict):
        raise Poison("record is not a JSON object")
    return d


def raw_rows(payload: bytes) -> list[dict]:
    ev = _load(payload)
    try:
        p = ev["payload"]
        return [{
            "event_id": ev["event_id"], "sensor_id": ev["sensor_id"], "sensor_boot_id": ev["sensor_boot_id"],
            "sequence": ev["sequence"], "replay_run_id": ev["replay_run_id"], "log_type": ev["log_type"],
            "event_time": ev["event_time"], "observation_time": timeutil.format_ms(contracts.observation_ms(ev)),
            "receiver_received_at": ev["receiver_received_at"], "capture_mode": ev["capture_mode"],
            "observation_coverage": ev["observation_coverage"], "uid": p.get("uid"), "src_ip": p.get("src_ip"),
            "src_port": p.get("src_port"), "dst_ip": p.get("dst_ip"), "dst_port": p.get("dst_port"), "proto": p.get("proto"),
            "event_json": payload.decode("utf-8"),
        }]
    except (KeyError, TypeError, ValueError) as e:
        raise Poison(f"missing field: {e}") from None


def feature_rows(payload: bytes) -> list[dict]:
    fr = _load(payload)
    try:
        return [{
            "feature_record_id": fr["feature_record_id"], "feature_schema_version": fr["feature_schema_version"],
            "detector": fr["detector"], "entity_type": fr["entity"]["type"], "entity_key": fr["entity"]["key"],
            "sensor_id": fr["sensor_id"], "window_start": fr["window_start"], "window_end": fr["window_end"],
            "computed_at": fr["computed_at"],
            "feature_values": {k: float(v) for k, v in fr["values"].items() if v is not None},
            "availability": fr["availability"], "capped": fr["capped"], "record_json": payload.decode("utf-8"),
        }]
    except (KeyError, TypeError, ValueError) as e:
        raise Poison(f"missing field: {e}") from None


def alert_rows(payload: bytes) -> list[dict]:
    a = _load(payload)
    errs = contracts.validate("alert", a)
    if errs:
        raise Poison(f"schema_violation: {errs[0][1]}")
    return [{
        "update_id": a["update_id"], "incident_id": a["incident_id"], "alert_id": a["alert_id"],
        "update_seq": a["update_seq"], "status": a["status"], "ts": a["timestamp"], "event_time": a["event_time"],
        "observation_time": a["observation_time"], "evidence_received_at": a["evidence_received_at"],
        "sensor_id": a["sensor_id"], "replay_run_id": a["replay_run_id"], "threat_class": a["threat_class"],
        "subtype": a["subtype"], "severity": a["severity"], "confidence": a["confidence"],
        "confidence_kind": a["confidence_kind"], "calibration_status": a["calibration_status"],
        "model_version": a["model_version"], "detector_version": a["detector_version"],
        "detection_method": a["detection_method"], "entity_type": a["entity"]["type"], "entity_key": a["entity"]["key"],
        "src_ip": a["src_ip"], "src_port": a["src_port"], "dst_ip": a["dst_ip"], "dst_port": a["dst_port"],
        "protocol": a["protocol"], "window_start": a["window_start"], "window_end": a["window_end"],
        "first_seen": a["first_seen"], "last_seen": a["last_seen"], "explanation": a["explanation"],
        "alert_json": payload.decode("utf-8"),
    }]


def invalid_rows(payload: bytes) -> list[dict]:
    q = _load(payload)
    try:
        return [{k: q[k] for k in ("invalid_id", "detected_at", "stage", "reason_code", "detail", "sensor_id",
                                   "sensor_boot_id", "sequence", "raw_sha256", "raw_size_bytes", "raw_excerpt")}]
    except KeyError as e:
        raise Poison(f"missing field: {e}") from None


def health_rows(payload: bytes) -> list[dict]:
    h = _load(payload)
    try:
        return [{
            "sensor_id": h["sensor_id"], "sensor_boot_id": h["sensor_boot_id"], "health_seq": h["health_seq"],
            "emitted_at": h["emitted_at"], "received_at": h["received_at"], "sender_state": h["sender_state"],
            "last_sequence_sent": h["last_sequence_sent"], "records_read_total": h["records_read_total"],
            "records_invalid_local_total": h["records_invalid_local_total"],
            "records_rejected_oversize_total": h["records_rejected_oversize_total"], "spool_bytes": h["spool_bytes"],
            "record_json": payload.decode("utf-8"),
        }]
    except KeyError as e:
        raise Poison(f"missing field: {e}") from None


class ClickHouseSink:
    def __init__(self, name: str, table: str, transform):
        self.name = name
        self.table = table
        self._transform = transform
        self._ch = None

    @property
    def ch(self) -> ClickHouseHTTP:
        if self._ch is None:
            self._ch = ch_from_env()
        return self._ch

    def transform(self, payload: bytes) -> list[dict]:
        return self._transform(payload)

    def write(self, rows: list[dict]) -> None:
        self.ch.insert_json(self.table, rows)

    def quarantine(self, items) -> None:
        self.ch.insert_json("sih.consumer_quarantine", [
            {"consumer": self.name, "topic": t, "partition": p, "offset": o, "reason": r[:1000],
             "payload": payload[:65536].decode("utf-8", errors="replace") if isinstance(payload, bytes) else
             base64.b64encode(payload).decode()} for t, p, o, r, payload in items])
