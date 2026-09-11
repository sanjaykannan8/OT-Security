"""Historical reads from ClickHouse (read-only user, bound parameters only)."""
from __future__ import annotations

import json

from sih_common import env
from sih_common.chttp import ClickHouseHTTP

LIST_COLUMNS = ("incident_id, update_seq, status, ts, threat_class, subtype, severity, confidence, confidence_kind, "
                "calibration_status, model_version, detection_method, entity_type, entity_key, src_ip, dst_ip, dst_port, "
                "sensor_id, first_seen, last_seen, explanation")
LATENCY_MS = "dateDiff('millisecond', evidence_received_at, ts)"


def reader() -> ClickHouseHTTP:
    return ClickHouseHTTP(env.env_str("CLICKHOUSE_URL", "http://clickhouse:8123"), env.env_str("CLICKHOUSE_USER", "sih_reader"),
                          env.secret_text("CLICKHOUSE_PASSWORD_FILE"), timeout=10)


class Queries:
    def __init__(self, ch: ClickHouseHTTP):
        self.ch = ch

    def incidents(self, since_minutes: int, severity: str, threat_class: str, status: str, q: str, limit: int) -> list[dict]:
        return self.ch.query(
            f"SELECT {LIST_COLUMNS} FROM sih.incidents_latest FINAL "
            "WHERE last_seen >= now64(3) - toIntervalMinute({since:UInt32}) "
            "AND ({sev:String} = '' OR severity = {sev:String}) "
            "AND ({cls:String} = '' OR threat_class = {cls:String}) "
            "AND ({st:String} = '' OR status = {st:String}) "
            "AND ({q:String} = '' OR positionCaseInsensitive(entity_key, {q:String}) > 0 "
            "     OR positionCaseInsensitive(explanation, {q:String}) > 0) "
            "ORDER BY ts DESC LIMIT {limit:UInt32}",
            {"since": since_minutes, "sev": severity, "cls": threat_class, "st": status, "q": q, "limit": limit})

    def incident(self, incident_id: str) -> dict | None:
        latest = self.ch.query("SELECT alert_json FROM sih.incidents_latest FINAL WHERE incident_id = {id:UUID}",
                               {"id": incident_id})
        if not latest:
            return None
        updates = self.ch.query("SELECT alert_json FROM sih.alert_updates FINAL WHERE incident_id = {id:UUID} "
                                "ORDER BY update_seq", {"id": incident_id})
        current = json.loads(latest[0]["alert_json"])
        ids = current["evidence"]["raw_event_ids"][:32]
        related = []
        if ids:
            arr = "[" + ",".join("'" + i + "'" for i in ids if len(i) == 36) + "]"
            related = [json.loads(r["event_json"]) for r in self.ch.query(
                "SELECT event_json FROM sih.raw_events FINAL WHERE event_id IN {ids:Array(UUID)} "
                "ORDER BY observation_time LIMIT 50", {"ids": arr})]
        return {"incident": current, "updates": [json.loads(u["alert_json"]) for u in updates], "related_events": related}

    def stats(self, window_minutes: int) -> dict:
        p = {"w": window_minutes}
        window = "last_seen >= now64(3) - toIntervalMinute({w:UInt32})"
        sev = self.ch.query(f"SELECT severity, status = 'resolved' AS resolved, count() AS n FROM sih.incidents_latest FINAL "
                            f"WHERE {window} GROUP BY severity, resolved", p)
        threats = self.ch.query(f"SELECT threat_class, count() AS n FROM sih.incidents_latest FINAL WHERE {window} "
                                "GROUP BY threat_class ORDER BY n DESC", p)
        rate = self.ch.query("SELECT toStartOfMinute(ts) AS minute, count() AS n FROM sih.alert_updates FINAL "
                             "WHERE ts >= now64(3) - toIntervalMinute({w:UInt32}) AND status != 'resolved' "
                             "GROUP BY minute ORDER BY minute", p)
        conf = self.ch.query(f"SELECT confidence_kind, calibration_status, if(isNull(confidence), -1, floor(confidence * 10) / 10) AS bucket, "
                             f"count() AS n FROM sih.incidents_latest FINAL WHERE {window} "
                             "GROUP BY confidence_kind, calibration_status, bucket ORDER BY bucket", p)
        lat = self.ch.query(
            f"SELECT count() AS n, quantilesExact(0.5, 0.9, 0.95, 0.99)({LATENCY_MS}) AS q, max({LATENCY_MS}) AS max_ms, "
            f"countIf({LATENCY_MS} > 5000) AS over_5s FROM sih.alert_updates FINAL "
            "WHERE ts >= now64(3) - toIntervalMinute({w:UInt32}) AND status IN ('new', 'escalated')", p)[0]
        q = lat.get("q") or [None] * 4
        return {
            "window_minutes": window_minutes,
            "severity": sev, "threat_classes": threats, "alert_rate_per_minute": rate, "confidence": conf,
            "detection_latency": {
                "definition": "Flink emission time minus receiver arrival of the evidence that made the alert eligible",
                "samples": lat["n"], "p50_ms": q[0], "p90_ms": q[1], "p95_ms": q[2], "p99_ms": q[3],
                "max_ms": lat["max_ms"] if lat["n"] else None, "over_5s": lat["over_5s"]},
        }

    def quarantine(self, limit: int) -> list[dict]:
        return self.ch.query("SELECT invalid_id, detected_at, stage, reason_code, detail, sensor_id, sequence, raw_size_bytes, "
                             "raw_excerpt FROM sih.invalid_events FINAL ORDER BY detected_at DESC LIMIT {limit:UInt32}",
                             {"limit": limit})
