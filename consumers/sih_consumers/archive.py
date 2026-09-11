"""Archive exporter, verifier and retention guard.

For every closed daily partition (ingest_day < today UTC): export `SELECT ... FINAL` as gzip JSONEachRow
to the object-locked MinIO archive bucket with a manifest, verify by reading the object back (sha256 and
row count, compared with ClickHouse), and only then allow the hot partition to be dropped once it is
older than the hot-retention period. There is no unconditional TTL: an unverified partition is never
deleted, and backlog is exported as a metric.

    python -m sih_consumers archive-exporter              # loop
    python -m sih_consumers.archive restore <table> <YYYY-MM-DD>
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import logging
import sys
import tempfile
import threading

from prometheus_client import Counter, Gauge

from sih_common import env, timeutil
from sih_consumers.clickhouse_sinks import ch_from_env

log = logging.getLogger("archive")
TABLES = ("raw_events", "features", "alert_updates", "invalid_events", "sensor_health")
BUCKET = "archive"

UNVERIFIED = Gauge("sih_archive_unverified_partitions", "Closed hot partitions without a verified archive")
VERIFIED = Counter("sih_archive_verified_total", "Partitions exported and verified")
DROPPED = Counter("sih_archive_hot_partitions_dropped_total", "Hot partitions dropped after verification")
FAILURES = Counter("sih_archive_failures_total", "Export or verification failures", ["stage"])


def minio_client():
    from minio import Minio
    endpoint = env.env_str("MINIO_ENDPOINT", "minio:9000")
    return Minio(endpoint, access_key=env.env_str("MINIO_ARCHIVE_USER", "archive"),
                 secret_key=env.secret_text("MINIO_ARCHIVE_SECRET_FILE"), secure=False)


class Archiver:
    def __init__(self, ch=None, s3=None, hot_days: int | None = None, today: dt.date | None = None):
        self.ch = ch or ch_from_env("CLICKHOUSE_ADMIN_USER", "sih_admin")
        self.s3 = s3 or minio_client()
        self.hot_days = hot_days if hot_days is not None else env.env_int("HOT_RETENTION_DAYS", 90)
        self._today = today

    def today(self) -> dt.date:
        return self._today or dt.datetime.now(dt.timezone.utc).date()

    def closed_partitions(self, table: str) -> list[str]:
        rows = self.ch.query("SELECT DISTINCT partition_id FROM system.parts WHERE database = 'sih' AND table = {t:String} "
                             "AND active ORDER BY partition_id", {"t": table})
        cutoff = self.today().strftime("%Y%m%d")
        return [r["partition_id"] for r in rows if r["partition_id"] < cutoff]

    def manifest(self, table: str, pid: str) -> dict | None:
        rows = self.ch.query("SELECT * FROM sih.archive_manifest FINAL WHERE table_name = {t:String} AND partition_id = {p:String}",
                             {"t": table, "p": pid})
        return rows[0] if rows else None

    def _record(self, **m) -> None:
        self.ch.insert_json("sih.archive_manifest", [{**m, "updated_at": timeutil.format_us(timeutil.now_us())}])

    @staticmethod
    def day(pid: str) -> str:
        return f"{pid[:4]}-{pid[4:6]}-{pid[6:8]}"

    def hot_count(self, table: str, pid: str) -> int:
        return int(self.ch.query(f"SELECT count() AS n FROM sih.{table} FINAL WHERE ingest_day = toDate({{d:String}})",
                                 {"d": self.day(pid)})[0]["n"])

    def export(self, table: str, pid: str) -> dict:
        day = self.day(pid)
        sha = hashlib.sha256()
        rows = 0
        with tempfile.TemporaryFile() as tmp:
            with gzip.GzipFile(fileobj=tmp, mode="wb", mtime=0) as gz:
                for chunk in self.ch.stream(f"SELECT * FROM sih.{table} FINAL WHERE ingest_day = toDate('{day}') "
                                            "ORDER BY tuple() FORMAT JSONEachRow"):
                    gz.write(chunk)
                    rows += chunk.count(b"\n")
            size = tmp.tell()
            tmp.seek(0)
            data = tmp.read()
        sha.update(data)
        digest = sha.hexdigest()
        key = f"{table}/ingest_day={day}/{table}-{day}-{digest[:16]}.jsonl.gz"
        self.s3.put_object(BUCKET, key, io.BytesIO(data), size, content_type="application/gzip")
        doc = {"table": table, "partition_id": pid, "ingest_day": day, "object_key": key, "rows": rows,
               "sha256": digest, "exported_at": timeutil.format_us(timeutil.now_us()), "format": "gzip JSONEachRow of SELECT ... FINAL"}
        body = json.dumps(doc, indent=2).encode()
        self.s3.put_object(BUCKET, key.replace(".jsonl.gz", ".manifest.json"), io.BytesIO(body), len(body),
                           content_type="application/json")
        self._record(table_name=table, partition_id=pid, object_key=key, rows=rows, sha256=digest,
                     min_ingested=f"{day}T00:00:00Z", max_ingested=f"{day}T23:59:59Z", status="exported",
                     exported_at=doc["exported_at"], verified_at=None)
        return doc

    def read_back(self, key: str) -> tuple[str, int, bytes]:
        resp = self.s3.get_object(BUCKET, key)
        try:
            data = resp.read()
        finally:
            resp.close()
            resp.release_conn()
        raw = gzip.decompress(data)
        return hashlib.sha256(data).hexdigest(), raw.count(b"\n"), raw

    def verify(self, table: str, pid: str, m: dict) -> bool:
        digest, rows, _ = self.read_back(m["object_key"])
        hot = self.hot_count(table, pid)
        if digest != m["sha256"] or rows != int(m["rows"]):
            FAILURES.labels("verify").inc()
            log.error("archive object mismatch for %s/%s", table, pid)
            return False
        if hot != rows:
            log.warning("hot partition %s/%s changed since export (%d vs %d rows); re-exporting", table, pid, hot, rows)
            self._record(**{k: m[k] for k in ("table_name", "partition_id", "object_key", "rows", "sha256", "min_ingested",
                                             "max_ingested", "exported_at")}, status="stale", verified_at=None)
            return False
        self._record(**{k: m[k] for k in ("table_name", "partition_id", "object_key", "rows", "sha256", "min_ingested",
                                         "max_ingested", "exported_at")}, status="verified",
                     verified_at=timeutil.format_us(timeutil.now_us()))
        VERIFIED.inc()
        return True

    def cycle(self) -> dict:
        summary = {"exported": 0, "verified": 0, "dropped": 0, "unverified": 0}
        cutoff = (self.today() - dt.timedelta(days=self.hot_days)).strftime("%Y%m%d")
        for table in TABLES:
            for pid in self.closed_partitions(table):
                try:
                    m = self.manifest(table, pid)
                    if m is None or m["status"] == "stale":
                        self.export(table, pid)
                        summary["exported"] += 1
                        m = self.manifest(table, pid)
                    if m["status"] == "exported":
                        if self.verify(table, pid, m):
                            summary["verified"] += 1
                        m = self.manifest(table, pid)
                    if m["status"] != "verified":
                        summary["unverified"] += 1
                        continue
                    if pid < cutoff:
                        self.ch.command(f"ALTER TABLE sih.{table} DROP PARTITION ID '{pid}'")
                        self._record(**{k: m[k] for k in ("table_name", "partition_id", "object_key", "rows", "sha256",
                                                         "min_ingested", "max_ingested", "exported_at", "verified_at")},
                                     status="deleted_hot")
                        DROPPED.inc()
                        summary["dropped"] += 1
                except Exception as e:
                    FAILURES.labels("cycle").inc()
                    summary["unverified"] += 1
                    log.error("archive cycle failed for %s/%s: %s", table, pid, e)
        UNVERIFIED.set(summary["unverified"])
        return summary

    def restore(self, table: str, day: str) -> int:
        pid = day.replace("-", "")
        m = self.manifest(table, pid)
        if m is None:
            raise SystemExit(f"no archive manifest for {table} {day}")
        digest, rows, raw = self.read_back(m["object_key"])
        if digest != m["sha256"] or rows != int(m["rows"]):
            raise SystemExit("archive object failed verification; refusing to restore")
        self.ch.insert_raw(f"sih.{table}", raw)
        return rows


def run_loop(stop: threading.Event) -> None:
    a = Archiver()
    interval = env.env_int("ARCHIVE_INTERVAL_S", 300)
    while not stop.is_set():
        try:
            log.info("archive cycle: %s", a.cycle())
        except Exception as e:
            FAILURES.labels("cycle").inc()
            log.error("archive cycle error (will retry): %s", e)
        stop.wait(interval)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "restore":
        print(json.dumps({"restored_rows": Archiver().restore(sys.argv[2], sys.argv[3])}))
    else:
        raise SystemExit("usage: python -m sih_consumers.archive restore <table> <YYYY-MM-DD>")
