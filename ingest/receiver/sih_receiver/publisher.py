"""Publish spooled records to Redpanda in spool order.

Idempotent, acks=all producer. The persisted cursor only advances over a contiguous prefix of acknowledged
records; after any delivery failure the publisher rebuilds the producer and resends from the cursor
(duplicates are removed downstream by event_id). This is ordinary acknowledged Kafka traffic inside the
SOC enclave, not traffic across the one-way link.
"""
from __future__ import annotations

import logging
import pathlib
import threading
import time
from collections import deque
from typing import Callable

from sih_receiver.spool import Position, Spool, read_position, write_position

log = logging.getLogger("receiver.publisher")
TOPICS = {1: "raw-events.v1", 2: "invalid-events.v1", 3: "sensor-health.v1"}


def kafka_producer_factory(bootstrap: str) -> Callable[[], object]:
    def make():
        from confluent_kafka import Producer
        return Producer({
            "bootstrap.servers": bootstrap,
            "client.id": "sih-receiver",
            "acks": "all",
            "enable.idempotence": True,
            "linger.ms": 5,
            "compression.type": "lz4",
            "message.timeout.ms": 30000,
            "queue.buffering.max.messages": 200000,
        })
    return make


class Publisher(threading.Thread):
    def __init__(self, spool: Spool, cursor_file: pathlib.Path, producer_factory: Callable[[], object],
                 published_counter=None, error_counter=None):
        super().__init__(name="publisher", daemon=True)
        self.spool = spool
        self.cursor_file = pathlib.Path(cursor_file)
        self.factory = producer_factory
        self.cursor: Position = read_position(self.cursor_file) or spool.first_position()
        self.healthy = False
        self._published = published_counter
        self._errors = error_counter
        self._stop_evt = threading.Event()

    def stop(self) -> None:
        self._stop_evt.set()

    def backlog_bytes(self) -> int:
        end = self.spool.end()
        if end[0] == self.cursor[0]:
            return max(0, end[1] - self.cursor[1])
        return self.spool.total_bytes

    def run(self) -> None:
        backoff = 0.5
        while not self._stop_evt.is_set():
            producer = None
            try:
                producer = self.factory()
                self.pump(producer)
                backoff = 0.5
            except Exception as e:  # rebuild the producer and resend from the cursor
                if self._errors is not None:
                    self._errors.inc()
                log.warning("publisher round failed; resending from cursor %s: %s", self.cursor, e)
            finally:
                if producer is not None:
                    try:
                        producer.flush(5)
                    except Exception:
                        pass
            self.healthy = False
            self._stop_evt.wait(backoff)
            backoff = min(10.0, backoff * 2)

    def pump(self, producer, max_idle_rounds: int | None = None) -> None:
        """Send in spool order until stopped or a delivery failure is reported (raises)."""
        read_pos = self.cursor
        in_flight: deque[Position] = deque()
        acked: set[Position] = set()
        failures: list = []
        last_persist = time.monotonic()
        idle_rounds = 0

        def on_delivery_for(end: Position):
            def cb(err, _msg):
                if err is not None:
                    failures.append(err)
                else:
                    acked.add(end)
                    if self._published is not None:
                        self._published.inc()
            return cb

        while not self._stop_evt.is_set():
            if failures:
                raise RuntimeError(f"delivery failed: {failures[0]}")
            limit = self.spool.synced_end()
            batch = self.spool.read(read_pos, limit, 2000) if len(in_flight) < 50000 else []
            for e in batch:
                while True:
                    try:
                        producer.produce(TOPICS[e.topic], value=e.value, key=e.key or None,
                                         timestamp=e.ts_ms if e.ts_ms > 0 else 0, on_delivery=on_delivery_for(e.end))
                        break
                    except BufferError:
                        producer.poll(0.05)
                in_flight.append(e.end)
                read_pos = e.end
            producer.poll(0 if batch else 0.02)
            advanced = False
            while in_flight and in_flight[0] in acked:
                acked.discard(in_flight[0])
                self.cursor = in_flight.popleft()
                advanced = True
            if advanced:
                self.healthy = True
            now = time.monotonic()
            if advanced and (now - last_persist >= 0.2 or not in_flight):
                write_position(self.cursor_file, self.cursor)
                self.spool.release(self.cursor)
                last_persist = now
            if not batch and not in_flight:
                idle_rounds += 1
                if max_idle_rounds is not None and idle_rounds >= max_idle_rounds:
                    return
            else:
                idle_rounds = 0
