"""Outward-only UDP writer.

The socket is never connected and never read: no acknowledgement, retransmission request or any other
return path exists. Loss while the receiver is down is expected and shows up only as a sequence gap on
the SOC side.
"""
from __future__ import annotations

import logging
import socket
import threading
import time

from sih_common.linkframe import TYPE_EVENT, LinkCodec

log = logging.getLogger("sender.link")


class LinkWriter:
    def __init__(self, host: str, port: int, key: bytes, redundancy: int = 1, frames_per_second: float = 20000.0):
        self.host, self.port = host, port
        self.codec = LinkCodec(key)
        self.redundancy = max(1, redundancy)
        self.fps = frames_per_second
        self.burst = max(64.0, frames_per_second / 50.0)
        self._tokens = self.burst
        self._last_refill = time.monotonic()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self._target = None
        self._last_resolve = 0.0
        self._lock = threading.Lock()
        self.frames_sent = 0
        self.records_sent = 0
        self.send_errors = 0
        self.last_sequence_sent = -1

    def send(self, ftype: int, sensor_id: str, boot_id: str, sequence: int, record: bytes) -> None:
        frames = self.codec.encode(ftype, sensor_id, boot_id, sequence, record)  # may raise RecordTooLarge
        with self._lock:
            for _ in range(self.redundancy):
                for f in frames:
                    self._acquire()
                    self._transmit(f)
            if ftype == TYPE_EVENT:
                self.records_sent += 1
                self.last_sequence_sent = sequence

    def _resolve(self):
        if self._target is not None:
            return self._target
        now = time.monotonic()
        if now - self._last_resolve < 1.0:
            return None
        self._last_resolve = now
        try:
            # SOC-internal service name resolution; never a lookup of observed traffic.
            info = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_DGRAM)
            self._target = info[0][4]
        except OSError:
            log.warning("link target unresolved; frames are being dropped")
            return None
        return self._target

    def _transmit(self, frame: bytes) -> None:
        target = self._resolve()
        if target is None:
            self.send_errors += 1
            return
        try:
            self._sock.sendto(frame, target)
            self.frames_sent += 1
        except OSError:
            self.send_errors += 1
            self._target = None

    def _acquire(self) -> None:
        while True:
            now = time.monotonic()
            self._tokens = min(self.burst, self._tokens + (now - self._last_refill) * self.fps)
            self._last_refill = now
            if self._tokens >= 1:
                self._tokens -= 1
                return
            time.sleep(max((1 - self._tokens) / self.fps, 0.0002))

    def close(self) -> None:
        self._sock.close()
