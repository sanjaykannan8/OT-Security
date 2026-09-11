"""Offline notifier: durable local notification log with idempotency on update_id.

A notification and its processed marker are one SQLite row (INSERT OR IGNORE on the update_id primary
key, WAL + synchronous=FULL), so a replayed update never produces a second notification. A JSONL export
is appended after commit for operators. No external delivery or remediation is configured; an external
webhook could not be exactly-once without recipient cooperation.
"""
from __future__ import annotations

import json
import pathlib
import sqlite3

from prometheus_client import Counter

from sih_common import env, timeutil
from sih_consumers.base import Poison

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SENT = Counter("sih_notifications_total", "Notifications recorded", ["severity"])
SKIPPED = Counter("sih_notifications_duplicate_total", "Replayed updates already notified")


class NotifierSink:
    name = "alerts-notifier"

    def __init__(self, directory: str | None = None, min_severity: str | None = None):
        d = pathlib.Path(directory or env.env_str("NOTIFIER_DIR", "/data/notifier"))
        d.mkdir(parents=True, exist_ok=True)
        self.export = d / "notifications.jsonl"
        self.min_rank = RANK[min_severity or env.env_str("NOTIFY_MIN_SEVERITY", "medium")]
        self.db = sqlite3.connect(d / "notifier.db", isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS notifications (
            update_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, status TEXT NOT NULL, severity TEXT NOT NULL,
            threat_class TEXT NOT NULL, entity TEXT NOT NULL, message TEXT NOT NULL, alert_ts TEXT NOT NULL,
            notified_at TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS quarantine (
            topic TEXT, partition INTEGER, offset INTEGER, reason TEXT, payload TEXT,
            PRIMARY KEY (topic, partition, offset))""")

    def transform(self, payload: bytes) -> list[dict]:
        try:
            a = json.loads(payload)
            if a.get("status") not in ("new", "escalated"):
                return []
            if RANK.get(a.get("severity"), -1) < self.min_rank:
                return []
            entity = f"{a['entity']['type']}={a['entity']['key']}"
            msg = f"[{a['severity'].upper()}] {a['threat_class']}/{a['subtype']} {entity}: {a['explanation']}"[:2000]
            return [{"update_id": a["update_id"], "incident_id": a["incident_id"], "status": a["status"],
                     "severity": a["severity"], "threat_class": a["threat_class"], "entity": entity,
                     "message": msg, "alert_ts": a["timestamp"]}]
        except (ValueError, KeyError, TypeError) as e:
            raise Poison(f"unparseable alert: {e}") from None

    def write(self, rows: list[dict]) -> None:
        now = timeutil.format_us(timeutil.now_us())
        inserted = []
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for r in rows:
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO notifications VALUES (?,?,?,?,?,?,?,?,?)",
                    (r["update_id"], r["incident_id"], r["status"], r["severity"], r["threat_class"], r["entity"],
                     r["message"], r["alert_ts"], now))
                if cur.rowcount == 1:
                    inserted.append({**r, "notified_at": now})
                else:
                    SKIPPED.inc()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        if inserted:
            with open(self.export, "a", encoding="utf-8") as f:
                for r in inserted:
                    f.write(json.dumps(r, ensure_ascii=True) + "\n")
                    SENT.labels(r["severity"]).inc()

    def quarantine(self, items) -> None:
        with self.db:
            self.db.executemany("INSERT OR IGNORE INTO quarantine VALUES (?,?,?,?,?)",
                                [(t, p, o, r, payload[:65536].decode("utf-8", "replace")) for t, p, o, r, payload in items])

    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM notifications").fetchone()[0]
