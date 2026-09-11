"""OpenSearch sink (search profile): alert updates by update_id, latest incident state by incident_id
with external_gte versioning on update_seq, so replays and out-of-order updates never regress state."""
from __future__ import annotations

import json

import httpx

from sih_common import env
from sih_consumers.base import PermanentWriteError, Poison

ALERTS = "sih-alerts-v1"
INCIDENTS = "sih-incidents-v1"
QUARANTINE = "sih-quarantine-v1"
KEYWORD = {"type": "keyword"}
MAPPING = {
    "dynamic": False,
    "properties": {
        "@timestamp": {"type": "date"}, "timestamp": {"type": "date"}, "observation_time": {"type": "date"},
        "update_id": KEYWORD, "incident_id": KEYWORD, "alert_id": KEYWORD, "update_seq": {"type": "integer"},
        "status": KEYWORD, "threat_class": KEYWORD, "subtype": KEYWORD, "severity": KEYWORD,
        "confidence": {"type": "float"}, "confidence_kind": KEYWORD, "calibration_status": KEYWORD,
        "model_version": KEYWORD, "detector_version": KEYWORD, "detection_method": KEYWORD,
        "entity": {"properties": {"type": KEYWORD, "key": KEYWORD}}, "src_ip": KEYWORD, "dst_ip": KEYWORD,
        "dst_port": {"type": "integer"}, "sensor_id": KEYWORD, "explanation": {"type": "text"},
        "evidence": {"type": "object", "enabled": False}, "top_features": {"type": "object", "enabled": False},
    },
}


class OpenSearchSink:
    name = "alerts-opensearch"

    def __init__(self, url: str | None = None):
        self.url = (url or env.env_str("OPENSEARCH_URL", "http://opensearch:9200")).rstrip("/")
        self.http = httpx.Client(timeout=15)
        self._ready = False

    def _ensure(self) -> None:
        if self._ready:
            return
        for index, mapping in ((ALERTS, MAPPING), (INCIDENTS, MAPPING), (QUARANTINE, {"dynamic": True})):
            r = self.http.head(f"{self.url}/{index}")
            if r.status_code == 404:
                r = self.http.put(f"{self.url}/{index}", json={"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                                                                "mappings": mapping})
                if r.status_code >= 400 and "resource_already_exists" not in r.text:
                    raise RuntimeError(f"index creation failed: {r.status_code} {r.text[:300]}")
        self._ready = True

    def transform(self, payload: bytes) -> list[dict]:
        try:
            a = json.loads(payload)
            _ = (a["update_id"], a["incident_id"], a["update_seq"], a["timestamp"])
        except (ValueError, KeyError, TypeError) as e:
            raise Poison(f"unparseable alert: {e}") from None
        return [a]

    def _bulk(self, lines: list[dict]) -> None:
        body = "\n".join(json.dumps(x, separators=(",", ":")) for x in lines) + "\n"
        r = self.http.post(f"{self.url}/_bulk", content=body.encode("utf-8"), headers={"Content-Type": "application/x-ndjson"})
        if r.status_code >= 500 or r.status_code == 429:
            raise RuntimeError(f"opensearch unavailable: {r.status_code}")
        if r.status_code >= 400:
            raise PermanentWriteError(f"bulk rejected: {r.status_code} {r.text[:300]}")
        res = r.json()
        if not res.get("errors"):
            return
        for item in res.get("items", []):
            st = next(iter(item.values())).get("status", 200)
            if st == 409:
                continue  # an equal or newer incident version is already indexed
            if st >= 500 or st == 429:
                raise RuntimeError(f"opensearch item status {st}")
            if st >= 400:
                raise PermanentWriteError(f"document rejected: {json.dumps(item)[:300]}")

    def write(self, rows: list[dict]) -> None:
        self._ensure()
        lines = []
        for a in rows:
            doc = {**a, "@timestamp": a["timestamp"]}
            lines += [{"index": {"_index": ALERTS, "_id": a["update_id"]}}, doc,
                      {"index": {"_index": INCIDENTS, "_id": a["incident_id"], "version": a["update_seq"],
                                 "version_type": "external_gte"}}, doc]
        self._bulk(lines)

    def quarantine(self, items) -> None:
        self._ensure()
        lines = []
        for t, p, o, reason, payload in items:
            lines += [{"index": {"_index": QUARANTINE, "_id": f"{t}-{p}-{o}"}},
                      {"topic": t, "partition": p, "offset": o, "reason": reason,
                       "payload": payload[:65536].decode("utf-8", "replace")}]
        self._bulk(lines)
