"""Receiver pipeline without sockets or Kafka: frame -> reassembly -> dedup -> validation -> spool.

It never transmits toward the sender network.
"""
from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import time

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from sih_common import contracts, ids, timeutil
from sih_common.env import atomic_write
from sih_common.linkframe import TYPE_HEALTH, FrameError, LinkCodec
from sih_receiver import dedup as dd
from sih_receiver.reassembly import Complete, Reassembler
from sih_receiver.spool import TOPIC_HEALTH, TOPIC_INVALID, TOPIC_RAW, Spool

log = logging.getLogger("receiver")

_CODE_TO_REASON = {"schema": "schema_violation", "unsupported_schema_version": "unsupported_schema_version"}


def _dumps(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


observation_ms = contracts.observation_ms  # Kafka record timestamp


def partition_key(ev: dict) -> bytes:
    uid = ev["payload"].get("uid")
    if uid:
        return f"{ev['sensor_id']}|{ev['sensor_boot_id']}|{ev['replay_run_id'] or ''}|{uid}".encode("utf-8")
    return ev["event_id"].encode("ascii")


class Metrics:
    def __init__(self, registry: CollectorRegistry):
        r = registry
        self.datagrams = Counter("receiver_datagrams_total", "Datagrams received", registry=r)
        self.frames_rejected = Counter("receiver_frames_rejected_total", "Frames rejected before reassembly", ["reason"], registry=r)
        self.records = Counter("receiver_records_total", "Reassembled records", ["type"], registry=r)
        self.accepted = Counter("receiver_records_accepted_total", "Records validated and spooled", ["topic"], registry=r)
        self.invalid = Counter("receiver_records_invalid_total", "Records quarantined", ["reason"], registry=r)
        self.dropped = Counter("receiver_dropped_total", "Records dropped without spooling", ["reason"], registry=r)
        self.quarantine_suppressed = Counter("receiver_quarantine_suppressed_total",
                                             "Invalid records counted but not quarantined (rate limit)", registry=r)
        self.validation = Histogram("receiver_validation_seconds", "Per-record parse + validate time", registry=r,
                                    buckets=(0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05))
        self.published = Counter("receiver_published_total", "Records acknowledged by the broker", registry=r)
        self.publish_errors = Counter("receiver_publish_errors_total", "Publisher rounds failed (records are resent)", registry=r)
        self.spool_bytes = Gauge("receiver_spool_bytes", "Bytes held in the durable spool", registry=r)
        self.spool_max = Gauge("receiver_spool_max_bytes", "Spool byte limit", registry=r)
        self.backlog = Gauge("receiver_publish_backlog_bytes", "Spooled bytes not yet acknowledged by the broker", registry=r)
        self.publisher_healthy = Gauge("receiver_publisher_healthy", "1 when the last publisher round delivered", registry=r)
        self.pending = Gauge("receiver_reassembly_pending", "Incomplete fragmented records", registry=r)
        self.missing = Gauge("link_missing_in_window", "Sequences inside the dedup window not (yet) received", registry=r)
        self.gaps = Gauge("link_gap_records_total", "Sequences that left the window without being received", registry=r)
        self.dups = Gauge("link_duplicate_records_total", "Duplicate records suppressed", registry=r)
        self.reordered = Gauge("link_reordered_records_total", "Records that filled an earlier gap", registry=r)
        self.stale = Gauge("link_stale_records_total", "Records older than the dedup window", registry=r)
        self.sensor_last_sent = Gauge("sensor_last_sequence_sent", "Last sequence the sensor reports sending", ["sensor_id"], registry=r)
        self.sensor_highest = Gauge("sensor_highest_sequence_received", "Highest event sequence received", ["sensor_id"], registry=r)
        self.sensor_age = Gauge("sensor_health_age_seconds", "Seconds since the last sensor health record", ["sensor_id"], registry=r)
        self.sensor_backlog = Gauge("sensor_backlog_bytes", "Sensor-reported unsent backlog", ["sensor_id"], registry=r)
        self.sensor_invalid = Gauge("sensor_records_invalid_local_total", "Records the sensor could not normalize", ["sensor_id"], registry=r)
        self.sensor_oversize = Gauge("sensor_records_rejected_oversize_total", "Records the sensor rejected as too large", ["sensor_id"], registry=r)


class ReceiverCore:
    def __init__(self, state_dir: pathlib.Path, link_key: bytes, spool_max_bytes: int,
                 segment_bytes: int = 64 * 1024 * 1024, registry: CollectorRegistry | None = None,
                 quarantine_per_second: int = 200):
        self.state_dir = pathlib.Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.codec = LinkCodec(link_key)
        self.reassembler = Reassembler()
        self.dedup = dd.DedupWindow()
        self.spool = Spool(self.state_dir / "spool", spool_max_bytes, segment_bytes)
        self.m = Metrics(registry or CollectorRegistry())
        self.m.spool_max.set(spool_max_bytes)
        self._health_seen: dict[str, int] = {}
        self._sensors: dict[str, dict] = {}
        self._q_rate = quarantine_per_second
        self._q_tokens = float(quarantine_per_second)
        self._q_refill = time.monotonic()
        self._last_snapshot = 0.0
        self._restore_dedup()

    # ------------------------------------------------------------------ restart

    def _restore_dedup(self) -> None:
        """Load the dedup snapshot and replay spool records written after it."""
        f = self.state_dir / "dedup.json"
        start = self.spool.first_position()
        if f.exists():
            snap = json.loads(f.read_text())
            self.dedup.restore(snap)
            seg, off = (int(x) for x in snap.get("spool_position", "0:0").split(":"))
            start = max(start, (seg, off))
        end = self.spool.end()
        n = 0
        while start < end:
            entries = self.spool.read(start, end, 5000)
            if not entries:
                break
            for e in entries:
                if e.topic == TOPIC_RAW and e.sensor_id:
                    self.dedup.mark(e.sensor_id, e.boot_id, e.sequence)
                    n += 1
                start = e.end
        log.info("dedup window restored (replayed %d spool records)", n)

    # ------------------------------------------------------------------ datagrams

    def handle_datagram(self, data: bytes, now_us: int) -> None:
        self.m.datagrams.inc()
        try:
            frame = self.codec.decode(data)
        except FrameError as e:
            self.m.frames_rejected.labels(e.reason).inc()
            self.quarantine(e.reason, str(e), None, None, None, data)
            return
        evicted = []
        c = self.reassembler.add(frame, now_us, evicted)
        for x in evicted:
            self.quarantine(x.reason, "reassembly limit reached", x.sensor_id, x.boot_id, x.sequence, None)
        if c is None:
            return
        if c.type == TYPE_HEALTH:
            self.m.records.labels("health").inc()
            self._health(c)
        else:
            self.m.records.labels("event").inc()
            self._event(c)

    def _event(self, c: Complete) -> None:
        cls = self.dedup.check(c.sensor_id, c.boot_id, c.sequence)
        if cls in (dd.DUPLICATE, dd.STALE):
            self.dedup.mark(c.sensor_id, c.boot_id, c.sequence)  # updates counters only
            return
        t0 = time.perf_counter()
        try:
            ev = json.loads(c.record.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            self.dedup.mark(c.sensor_id, c.boot_id, c.sequence)
            self.quarantine("json_parse_error", "record is not valid UTF-8 JSON", c.sensor_id, c.boot_id, c.sequence, c.record)
            return
        reason, detail = self._validate_event(ev, c)
        self.m.validation.observe(time.perf_counter() - t0)
        if reason:
            self.dedup.mark(c.sensor_id, c.boot_id, c.sequence)
            self.quarantine(reason, detail, c.sensor_id, c.boot_id, c.sequence, c.record)
            return
        if not self.spool.append(TOPIC_RAW, partition_key(ev), c.sensor_id, c.boot_id, c.sequence,
                                 observation_ms(ev), _dumps(ev)):
            self.m.dropped.labels("spool_full").inc()
            return  # not marked: a redundant copy may still be accepted once space frees
        self.dedup.mark(c.sensor_id, c.boot_id, c.sequence)
        self.m.accepted.labels("raw-events.v1").inc()

    def _validate_event(self, ev, c: Complete) -> tuple[str | None, str]:
        if not isinstance(ev, dict):
            return "json_parse_error", "record is not a JSON object"
        ev["receiver_received_at"] = timeutil.format_us(c.received_at_us)
        errs = contracts.validate("event", ev)
        if errs:
            code = errs[0][0]
            reason = _CODE_TO_REASON.get(code, "availability_violation")
            return reason, "; ".join(m for _, m in errs[:3])
        if (ev["sensor_id"], ev["sensor_boot_id"], ev["sequence"]) != (c.sensor_id, c.boot_id, c.sequence):
            return "schema_violation", "envelope identity does not match link frame identity"
        sha = ev["original_record_sha256"]
        orig = ev["original_record"]
        if orig is not None and hashlib.sha256(orig.encode("utf-8")).hexdigest() != sha:
            return "schema_violation", "original_record_sha256 does not match original_record"
        if ids.event_id(c.sensor_id, c.boot_id, c.sequence, sha) != ev["event_id"]:
            return "schema_violation", "event_id is not the deterministic id for sensor/boot/sequence/hash"
        return None, ""

    def _health(self, c: Complete) -> None:
        key = f"{c.sensor_id}|{c.boot_id}"
        if c.sequence <= self._health_seen.get(key, -1):
            return  # duplicate or reordered health record
        self._health_seen[key] = c.sequence
        try:
            h = json.loads(c.record.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            self.quarantine("json_parse_error", "health record is not valid UTF-8 JSON", c.sensor_id, c.boot_id, c.sequence, c.record)
            return
        if isinstance(h, dict):
            h["received_at"] = timeutil.format_us(c.received_at_us)
        errs = contracts.validate("sensor_health", h)
        if errs:
            self.quarantine(_CODE_TO_REASON.get(errs[0][0], "schema_violation"), "; ".join(m for _, m in errs[:3]),
                            c.sensor_id, c.boot_id, c.sequence, c.record)
            return
        if (h["sensor_id"], h["sensor_boot_id"]) != (c.sensor_id, c.boot_id):
            self.quarantine("schema_violation", "health identity does not match link frame identity",
                            c.sensor_id, c.boot_id, c.sequence, c.record)
            return
        self._sensors[c.sensor_id] = {"boot": c.boot_id, "at": time.monotonic(), "rec": h}
        sid = c.sensor_id
        self.m.sensor_last_sent.labels(sid).set(-1 if h["last_sequence_sent"] is None else h["last_sequence_sent"])
        self.m.sensor_backlog.labels(sid).set(h["spool_bytes"])
        self.m.sensor_invalid.labels(sid).set(h["records_invalid_local_total"])
        self.m.sensor_oversize.labels(sid).set(h["records_rejected_oversize_total"])
        if self.spool.append(TOPIC_HEALTH, sid.encode("ascii"), None, None, -1, 0, _dumps(h)):
            self.m.accepted.labels("sensor-health.v1").inc()
        else:
            self.m.dropped.labels("spool_full").inc()

    # ------------------------------------------------------------------ quarantine

    def quarantine(self, reason: str, detail: str, sensor_id, boot_id, seq, raw: bytes | None) -> None:
        """Always counted; written to invalid-events.v1 subject to a rate limit."""
        self.m.invalid.labels(reason).inc()
        now = time.monotonic()
        self._q_tokens = min(float(self._q_rate), self._q_tokens + (now - self._q_refill) * self._q_rate)
        self._q_refill = now
        if self._q_tokens < 1:
            self.m.quarantine_suppressed.inc()
            return
        self._q_tokens -= 1
        sha = hashlib.sha256(raw).hexdigest() if raw is not None else None
        excerpt = None
        if raw is not None and reason not in ("frame_hmac_invalid", "frame_malformed"):
            excerpt = raw.decode("utf-8", errors="replace")[:2048]
        rec = {
            "invalid_schema_version": "1.0.0",
            "invalid_id": ids.invalid_id("receiver", reason, sha, sensor_id, boot_id, seq),
            "detected_at": timeutil.format_us(timeutil.now_us()),
            "stage": "receiver",
            "reason_code": reason,
            "detail": (detail or "")[:512],
            "sensor_id": sensor_id[:63] if sensor_id else None,
            "sensor_boot_id": boot_id,
            "sequence": seq if isinstance(seq, int) and seq >= 0 else None,
            "raw_sha256": sha,
            "raw_size_bytes": len(raw) if raw is not None else 0,
            "raw_excerpt": excerpt,
        }
        self.spool.append(TOPIC_INVALID, rec["invalid_id"].encode("ascii"), None, None, -1, 0, _dumps(rec))

    # ------------------------------------------------------------------ periodic

    def housekeeping(self) -> None:
        for x in self.reassembler.expire(timeutil.now_us()):
            self.quarantine(x.reason, "fragments incomplete", x.sensor_id, x.boot_id, x.sequence, None)
        synced = self.spool.sync()
        now = time.monotonic()
        m = self.m
        m.spool_bytes.set(self.spool.total_bytes)
        m.pending.set(self.reassembler.pending_count())
        m.missing.set(self.dedup.missing_in_window())
        m.gaps.set(self.dedup.gaps_total)
        m.dups.set(self.dedup.duplicates_total)
        m.reordered.set(self.dedup.reordered_total)
        m.stale.set(self.dedup.stale_total)
        for sid, s in self._sensors.items():
            m.sensor_age.labels(sid).set(now - s["at"])
            m.sensor_highest.labels(sid).set(self.dedup.highest(sid, s["boot"]))
        if now - self._last_snapshot >= 1.0:
            snap = self.dedup.snapshot()
            snap["spool_position"] = f"{synced[0]}:{synced[1]}"
            atomic_write(self.state_dir / "dedup.json", json.dumps(snap).encode("utf-8"))
            self._last_snapshot = now
