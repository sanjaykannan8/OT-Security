"""Bounded fragment reassembly: at most `max_pending` incomplete records and a completion timeout.

Duplicate fragments (link redundancy) are ignored. Used by the receive thread only.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from sih_common.linkframe import Frame


@dataclass
class Complete:
    type: int
    sensor_id: str
    boot_id: str
    sequence: int
    record: bytes
    received_at_us: int


@dataclass
class Expired:
    reason: str
    sensor_id: str
    boot_id: str
    sequence: int


class Reassembler:
    def __init__(self, max_pending: int = 4096, timeout_us: int = 2_000_000):
        self.max_pending = max_pending
        self.timeout_us = timeout_us
        self._pending: OrderedDict[tuple, list] = OrderedDict()  # key -> [chunks, total, first_seen_us, received]

    def pending_count(self) -> int:
        return len(self._pending)

    def add(self, f: Frame, now_us: int, expired: list[Expired]) -> Complete | None:
        if f.frag_count == 1:
            return Complete(f.type, f.sensor_id, f.boot_id, f.sequence, f.chunk, now_us)
        key = (f.type, f.sensor_id, f.boot_id, f.sequence)
        p = self._pending.get(key)
        if p is None:
            if len(self._pending) >= self.max_pending:
                k, _ = self._pending.popitem(last=False)
                expired.append(Expired("fragment_overflow", k[1], k[2], k[3]))
            p = [[None] * f.frag_count, f.total_length, now_us, 0]
            self._pending[key] = p
        elif len(p[0]) != f.frag_count or p[1] != f.total_length:
            del self._pending[key]
            expired.append(Expired("frame_malformed", f.sensor_id, f.boot_id, f.sequence))
            return None
        if p[0][f.frag_index] is None:
            p[0][f.frag_index] = f.chunk
            p[3] += 1
        if p[3] < f.frag_count:
            return None
        del self._pending[key]
        return Complete(f.type, f.sensor_id, f.boot_id, f.sequence, b"".join(p[0]), now_us)

    def expire(self, now_us: int) -> list[Expired]:
        out = []
        while self._pending:
            key, p = next(iter(self._pending.items()))
            if now_us - p[2] < self.timeout_us:
                break  # insertion-ordered: the rest are younger
            self._pending.popitem(last=False)
            out.append(Expired("fragment_timeout", key[1], key[2], key[3]))
        return out
