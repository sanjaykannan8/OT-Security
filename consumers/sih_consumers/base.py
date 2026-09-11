"""Consume -> transform -> durable write -> commit, with bounded poison handling.

Transient storage errors retry forever with backoff and never commit (offsets stay put, the broker
retention bounds the outage). A record that cannot be transformed, or that storage rejects three times,
is quarantined with a reason and its offset advances.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from prometheus_client import Counter, Gauge, Histogram

from sih_common.chttp import ClickHouseError

log = logging.getLogger("consumer")

WRITTEN = Counter("sih_consumer_records_written_total", "Records durably written", ["consumer"])
ERRORS = Counter("sih_consumer_write_errors_total", "Failed write attempts (offsets held)", ["consumer"])
POISON = Counter("sih_consumer_poison_records_total", "Records quarantined", ["consumer", "reason"])
COMMITS = Counter("sih_consumer_commits_total", "Offset commits after durable writes", ["consumer"])
LAG = Gauge("sih_consumer_lag_records", "High watermark minus consumer position", ["consumer"])
BATCH = Histogram("sih_consumer_batch_seconds", "Durable write time per batch", ["consumer"],
                  buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))


class Poison(Exception):
    """The record can never be written (e.g. unparseable)."""


class PermanentWriteError(Exception):
    """Storage rejected the data itself (not an availability problem)."""


@dataclass
class Item:
    topic: str
    partition: int
    offset: int
    payload: bytes
    rows: list = field(default_factory=list)


def is_permanent(e: Exception) -> bool:
    if isinstance(e, PermanentWriteError):
        return True
    if isinstance(e, ClickHouseError):
        return e.permanent
    return isinstance(e, (TypeError, ValueError))


def durable_write(sink, items: list[Item], stop: threading.Event) -> bool:
    """Write all rows (and quarantine records). Returns False only if stopped before success."""
    poison: list[tuple[Item, str]] = []
    good = [i for i in items if i.rows]
    permanent_attempts = 0
    transient_attempts = 0
    while not stop.is_set():
        try:
            t0 = time.perf_counter()
            rows = [r for i in good for r in i.rows]
            if rows:
                sink.write(rows)
                WRITTEN.labels(sink.name).inc(len(rows))
            if poison:
                sink.quarantine([(i.topic, i.partition, i.offset, reason, i.payload) for i, reason in poison])
                for _, reason in poison:
                    POISON.labels(sink.name, reason.split(":")[0]).inc()
            BATCH.labels(sink.name).observe(time.perf_counter() - t0)
            return True
        except Exception as e:  # classify and retry
            ERRORS.labels(sink.name).inc()
            if is_permanent(e) and good:
                permanent_attempts += 1
                log.warning("storage rejected batch (%d/3): %s", permanent_attempts, str(e)[:300])
                if permanent_attempts >= 3:
                    still_good = []
                    for i in good:  # isolate the rejected records
                        try:
                            sink.write(i.rows)
                            WRITTEN.labels(sink.name).inc(len(i.rows))
                        except Exception as e2:
                            if not is_permanent(e2):
                                still_good.append(i)
                                continue
                            poison.append((i, f"write_rejected: {str(e2)[:300]}"))
                    good = still_good
                continue
            transient_attempts += 1
            delay = min(30.0, 0.5 * 2 ** min(transient_attempts, 6))
            log.warning("storage unavailable (attempt %d, retry in %.1fs): %s", transient_attempts, delay, str(e)[:300])
            stop.wait(delay)
    return False


def _update_lag(consumer, name: str) -> None:
    total = 0
    try:
        for tp in consumer.assignment():
            lo, hi = consumer.get_watermark_offsets(tp, timeout=2, cached=False)
            pos = consumer.position([tp])[0].offset
            total += max(0, hi - (pos if pos >= 0 else lo))
        LAG.labels(name).set(total)
    except Exception as e:  # lag is observability only
        log.debug("lag update failed: %s", e)


def run_consumer(sink, topic: str, group: str, bootstrap: str, stop: threading.Event,
                 batch_max: int = 2000, batch_timeout_s: float = 0.5) -> None:
    from confluent_kafka import Consumer
    consumer = Consumer({
        "bootstrap.servers": bootstrap,
        "group.id": group,
        "client.id": f"{sink.name}-{topic}",
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "enable.partition.eof": False,
        "max.poll.interval.ms": 600000,
        "session.timeout.ms": 30000,
    })
    consumer.subscribe([topic])
    log.info("consumer %s subscribed to %s as %s", sink.name, topic, group)
    last_lag = 0.0
    try:
        while not stop.is_set():
            msgs = consumer.consume(num_messages=batch_max, timeout=batch_timeout_s)
            items = []
            for m in msgs:
                if m.error():
                    log.warning("kafka error: %s", m.error())
                    continue
                it = Item(m.topic(), m.partition(), m.offset(), m.value() or b"")
                try:
                    it.rows = sink.transform(it.payload)
                except Poison as e:
                    it.rows = []
                    items.append(it)
                    it_reason = f"transform: {str(e)[:300]}"
                    try:
                        sink.quarantine([(it.topic, it.partition, it.offset, it_reason, it.payload)])
                        POISON.labels(sink.name, "transform").inc()
                    except Exception:
                        # Quarantine store unavailable: hold offsets and retry the batch later.
                        ERRORS.labels(sink.name).inc()
                        stop.wait(2.0)
                        raise
                    continue
                items.append(it)
            if items:
                if not durable_write(sink, items, stop):
                    break
                consumer.commit(asynchronous=False)
                COMMITS.labels(sink.name).inc()
            now = time.monotonic()
            if now - last_lag >= 10:
                _update_lag(consumer, sink.name)
                last_lag = now
    finally:
        consumer.close()
        log.info("consumer %s stopped", sink.name)
