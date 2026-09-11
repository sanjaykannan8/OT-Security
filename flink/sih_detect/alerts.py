"""Findings, alert (incident update) and feature record construction.

A finding is the detector-side dict; the incident correlator turns findings into alert.v1 updates.
All numbers are sanitized (finite, rounded) so the JSON is strict.
"""
from __future__ import annotations

import json
import math
import time

from sih_common import ids, timeutil

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def num(v, digits: int = 6):
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        if isinstance(v, float) and not math.isfinite(v):
            return None
        return round(v, digits) if isinstance(v, float) else v
    return v


def to_json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def finding(*, detector, threat_class, subtype, entity_type, entity_key, severity, score, method,
            detector_version, feature_schema_version, first, last, window_start_ms, window_end_ms,
            observed, thresholds, baseline=None, unavailable=(), capped=(), coverage="unknown",
            src_ip=None, src_port=None, dst_ip=None, dst_port=None, protocol=None, flow_id=None,
            model_version=None, calibration_status=None, confidence_kind=None, model_eligible=False,
            model_reason=None, raw_event_ids=(), evidence_count=0, top_features=(), explanation="") -> dict:
    """`first`/`last` are the earliest and latest contributing events (need obs_ms, event_time_us,
    offset_us, received_us, sensor_id, run)."""
    if confidence_kind is None:
        confidence_kind = "heuristic_score" if score is not None else "unavailable"
    if calibration_status is None:
        calibration_status = "uncalibrated" if confidence_kind == "heuristic_score" else "not_applicable"
    return {
        "detector": detector, "threat_class": threat_class, "subtype": subtype,
        "entity_type": entity_type, "entity_key": str(entity_key)[:320], "severity": severity,
        "score": None if confidence_kind == "unavailable" else num(max(0.0, min(1.0, float(score)))),
        "confidence_kind": confidence_kind, "calibration_status": calibration_status,
        "model_version": model_version, "detector_version": detector_version,
        "feature_schema_version": feature_schema_version, "method": method,
        "obs_ms": last["obs_ms"], "event_time_us": last["event_time_us"], "offset_us": last["offset_us"],
        "received_us": last["received_us"], "sensor_id": last["sensor_id"], "run": last.get("run"),
        "first_seen_ms": min(first["obs_ms"], last["obs_ms"]), "last_seen_ms": last["obs_ms"],
        "window_start_ms": min(window_start_ms, window_end_ms), "window_end_ms": window_end_ms,
        "flow_id": flow_id[:200] if flow_id else None,
        "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol,
        "observed": {k: num(v) if not isinstance(v, str) else v[:255] for k, v in list(observed.items())[:32]},
        "thresholds": {k: num(v) for k, v in list(thresholds.items())[:16]},
        "baseline": {k: num(v) for k, v in list((baseline or {}).items())[:16]},
        "coverage": coverage, "unavailable": sorted(set(unavailable))[:64], "capped": sorted(set(capped))[:64],
        "model_eligible": bool(model_eligible), "model_reason": model_reason,
        "raw_event_ids": list(raw_event_ids)[-32:], "evidence_count": int(evidence_count),
        "top_features": [
            {"name": n, "value": num(v), "contribution": num(c), "unit": u} for n, v, c, u in list(top_features)[:10]
        ],
        "explanation": explanation[:1024],
    }


def alert_record(f: dict, incident_id: str, update_seq: int, status: str, now_ms: int | None = None) -> dict:
    now_us = (now_ms if now_ms is not None else int(time.time() * 1000)) * 1000
    fmt = timeutil.format_ms
    return {
        "alert_schema_version": "1.0.0",
        "alert_id": ids.alert_id(f["detector"], f["entity_type"], f["entity_key"], f["window_end_ms"], f["subtype"]),
        "incident_id": incident_id,
        "update_id": ids.update_id(incident_id, update_seq),
        "update_seq": update_seq,
        "status": status,
        "timestamp": timeutil.format_us(now_us),
        "event_time": timeutil.format_us(f["event_time_us"]),
        "observation_time": fmt(f["obs_ms"]),
        "replay_time_offset_us": f["offset_us"],
        "evidence_received_at": timeutil.format_us(f["received_us"]),
        "sensor_id": f["sensor_id"],
        "replay_run_id": f["run"],
        "flow_id": f["flow_id"],
        "src_ip": f["src_ip"], "src_port": f["src_port"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
        "protocol": f["protocol"],
        "entity": {"type": f["entity_type"], "key": f["entity_key"]},
        "threat_class": f["threat_class"],
        "subtype": f["subtype"],
        "severity": f["severity"],
        "confidence": f["score"],
        "confidence_kind": f["confidence_kind"],
        "calibration_status": f["calibration_status"],
        "model_version": f["model_version"],
        "detector_version": f["detector_version"],
        "feature_schema_version": f["feature_schema_version"],
        "detection_method": f["method"],
        "evidence": {
            "observed": f["observed"],
            "thresholds": f["thresholds"],
            "baseline": f["baseline"],
            "visibility": {"observation_coverage": f["coverage"], "unavailable_features": f["unavailable"],
                           "capped_features": f["capped"]},
            "model_eligibility": {"eligible": f["model_eligible"], "reason": f["model_reason"]},
            "raw_event_ids": f["raw_event_ids"],
            "raw_event_ids_truncated": f["evidence_count"] > len(f["raw_event_ids"]),
            "evidence_count": f["evidence_count"],
        },
        "top_features": f["top_features"],
        "explanation": f["explanation"],
        "window_start": fmt(f["window_start_ms"]),
        "window_end": fmt(f["window_end_ms"]),
        "first_seen": fmt(f["first_seen_ms"]),
        "last_seen": fmt(f["last_seen_ms"]),
        "dedup_key": f"{f['threat_class']}|{f['entity_type']}|{f['entity_key']}"[:400],
    }


def feature_record(detector: str, feature_schema_version: str, entity_type: str, entity_key: str, sensor_id: str,
                   window_start_ms: int, window_end_ms: int, values: dict, unavailable: dict | None = None,
                   capped=()) -> dict:
    """`unavailable` maps feature name -> availability state for features whose value is None."""
    unavailable = unavailable or {}
    vals = {k: num(v) for k, v in values.items()}
    avail = {k: unavailable.get(k, "UNKNOWN") for k, v in vals.items() if v is None}
    return {
        "feature_record_schema_version": "1.0.0",
        "feature_record_id": ids.feature_record_id(detector, entity_type, entity_key, window_end_ms),
        "feature_schema_version": feature_schema_version,
        "detector": detector,
        "entity": {"type": entity_type, "key": str(entity_key)[:320]},
        "sensor_id": sensor_id,
        "window_start": timeutil.format_ms(min(window_start_ms, window_end_ms)),
        "window_end": timeutil.format_ms(window_end_ms),
        "computed_at": timeutil.format_us(timeutil.now_us()),
        "values": vals,
        "availability": avail,
        "capped": [c for c in capped if vals.get(c) is not None],
    }


def rate_limited(state: dict, now_obs_ms: int, min_interval_ms: int, field: str = "last_feature_ms") -> bool:
    """True when a feature record may be emitted now; updates the state dict in place."""
    last = state.get(field)
    if last is not None and now_obs_ms - last < min_interval_ms:
        return False
    state[field] = now_obs_ms
    return True
