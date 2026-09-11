"""Live alert fan-out for SSE.

A dedicated consumer group (alerts-live-api-v1) reads alerts.v1 into a bounded ring buffer. Each client
gets a bounded queue; a slow client is disconnected with a resync instruction instead of slowing the
consumer, and the consumer never backpressures detection (it reads the broker independently).
Event ids are "<process nonce>-<sequence>", so a client reconnecting to the same process resumes from
Last-Event-ID, and after an API restart it is told to resynchronize from REST history.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import threading
import time
from collections import deque

from prometheus_client import Counter, Gauge, Histogram

from sih_common import timeutil

log = logging.getLogger("api.live")
CLIENTS = Gauge("sih_api_sse_clients", "Connected SSE clients")
DISCONNECTS = Counter("sih_api_sse_disconnects_total", "SSE clients disconnected by the server", ["reason"])
RECEIVED = Counter("sih_api_alerts_received_total", "Alert updates consumed by the API live consumer")
LATENCY = Histogram("sih_api_visible_latency_seconds", "API arrival minus evidence_received_at (new/escalated)",
                    buckets=(0.1, 0.25, 0.5, 1, 1.5, 2, 3, 5, 10, 30, 60, 300))


class LiveHub:
    def __init__(self, ring_size: int = 5000, client_queue: int = 1000):
        self.nonce = secrets.token_hex(4)
        self.ring: deque[tuple[int, str]] = deque(maxlen=ring_size)
        self.seq = 0
        self.client_queue = client_queue
        self.clients: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.latencies: deque[float] = deque(maxlen=2000)
        self.consumer_ok = False
        self.last_message_at: float | None = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- producer side (consumer thread)

    def publish(self, raw: str) -> None:
        arrival_us = timeutil.now_us()
        try:
            a = json.loads(raw)
            if a.get("status") in ("new", "escalated"):
                lat = (arrival_us - timeutil.parse_us(a["evidence_received_at"])) / 1e6
                if lat >= 0:
                    LATENCY.observe(lat)
                    self.latencies.append(lat)
            a["api_received_at"] = timeutil.format_us(arrival_us)
            raw = json.dumps(a, separators=(",", ":"))
        except (ValueError, KeyError):
            return
        with self._lock:
            self.seq += 1
            item = (self.seq, raw)
            self.ring.append(item)
        RECEIVED.inc()
        self.last_message_at = time.time()
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self._fanout, item)

    def _fanout(self, item) -> None:
        for q in list(self.clients):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                self.clients.discard(q)
                DISCONNECTS.labels("slow").inc()
                try:
                    q.get_nowait()
                    q.put_nowait(None)  # sentinel: tell the stream to send resync and close
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    # ---------------------------------------------------------------- client side

    def backlog_after(self, last_event_id: str | None) -> tuple[list, bool]:
        """Items after the given id, and whether the client must resync."""
        if not last_event_id:
            return [], False
        try:
            nonce, seq = last_event_id.rsplit("-", 1)
            seq = int(seq)
        except ValueError:
            return [], True
        with self._lock:
            ring = list(self.ring)
        if nonce != self.nonce or (ring and seq < ring[0][0] - 1):
            return [], True
        return [i for i in ring if i[0] > seq], False

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.client_queue)
        self.clients.add(q)
        CLIENTS.set(len(self.clients))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.clients.discard(q)
        CLIENTS.set(len(self.clients))

    def latency_summary(self) -> dict:
        xs = sorted(self.latencies)
        if not xs:
            return {"samples": 0}

        def pct(p):
            return round(xs[min(len(xs) - 1, int(p * len(xs)))], 3)
        return {"samples": len(xs), "p50_s": pct(0.5), "p90_s": pct(0.9), "p95_s": pct(0.95), "p99_s": pct(0.99),
                "max_s": round(xs[-1], 3), "over_5s": sum(1 for x in xs if x > 5)}


def consume_forever(hub: LiveHub, bootstrap: str, stop: threading.Event) -> None:
    from confluent_kafka import Consumer
    while not stop.is_set():
        try:
            c = Consumer({"bootstrap.servers": bootstrap, "group.id": "alerts-live-api-v1", "client.id": "sih-api-live",
                          "enable.auto.commit": True, "auto.commit.interval.ms": 1000, "auto.offset.reset": "latest"})
            c.subscribe(["alerts.v1"])
            hub.consumer_ok = True
            while not stop.is_set():
                msg = c.poll(0.5)
                if msg is None:
                    continue
                if msg.error():
                    log.warning("live consumer error: %s", msg.error())
                    continue
                hub.publish(msg.value().decode("utf-8", errors="replace"))
            c.close()
        except Exception as e:
            hub.consumer_ok = False
            log.warning("live consumer failed, retrying: %s", e)
            stop.wait(3)
