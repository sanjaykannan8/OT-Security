"""Per-(sensor, boot) sliding sequence window for duplicate suppression and gap accounting.

A gap is counted when a sequence leaves the window without having been received. Used by the receive
thread only; snapshots are persisted with the spool position they reflect.
"""
from __future__ import annotations

import base64
from collections import OrderedDict

WINDOW = 65536
MAX_STREAMS = 64
NEW, REORDERED, DUPLICATE, STALE = "new", "reordered", "duplicate", "stale"


class _Stream:
    __slots__ = ("base", "highest", "missing", "bits")

    def __init__(self):
        self.base = -1        # first sequence ever seen; earlier sequences are never gaps
        self.highest = -1
        self.missing = 0      # sequences inside the window not (yet) received
        self.bits = bytearray(WINDOW // 8)

    def get(self, seq: int) -> bool:
        i = seq & (WINDOW - 1)
        return bool(self.bits[i >> 3] & (1 << (i & 7)))

    def set(self, seq: int, value: bool) -> None:
        i = seq & (WINDOW - 1)
        if value:
            self.bits[i >> 3] |= 1 << (i & 7)
        else:
            self.bits[i >> 3] &= ~(1 << (i & 7)) & 0xFF


class DedupWindow:
    def __init__(self):
        self._streams: OrderedDict[str, _Stream] = OrderedDict()
        self.gaps_total = 0
        self.duplicates_total = 0
        self.reordered_total = 0
        self.stale_total = 0

    @staticmethod
    def _key(sensor_id: str, boot_id: str) -> str:
        return f"{sensor_id}|{boot_id}"

    def check(self, sensor_id: str, boot_id: str, seq: int) -> str:
        """Classify without recording."""
        s = self._streams.get(self._key(sensor_id, boot_id))
        if s is None or s.highest < 0 or seq > s.highest:
            return NEW
        if seq <= s.highest - WINDOW or seq < s.base:
            return STALE
        return DUPLICATE if s.get(seq) else REORDERED

    def mark(self, sensor_id: str, boot_id: str, seq: int) -> str:
        """Record a sequence as received; returns its classification before recording."""
        key = self._key(sensor_id, boot_id)
        s = self._streams.get(key)
        if s is None:
            s = self._streams[key] = _Stream()
            while len(self._streams) > MAX_STREAMS:
                self._streams.popitem(last=False)
        else:
            self._streams.move_to_end(key)
        if s.highest < 0:
            s.base = s.highest = seq
            s.set(seq, True)
            return NEW
        if seq > s.highest:
            delta = seq - s.highest
            if delta > WINDOW:
                # Everything in the window leaves it; unfilled positions become gaps.
                self.gaps_total += s.missing + (delta - WINDOW)
                s.bits[:] = bytes(len(s.bits))
                s.missing = WINDOW - 1
            else:
                for q in range(s.highest + 1, seq + 1):
                    evicted = q - WINDOW
                    if evicted >= s.base and not s.get(evicted):
                        self.gaps_total += 1
                        s.missing -= 1
                    s.set(q, False)
                s.missing += delta - 1
            s.highest = seq
            s.set(seq, True)
            return NEW
        if seq <= s.highest - WINDOW or seq < s.base:
            self.stale_total += 1
            return STALE
        if s.get(seq):
            self.duplicates_total += 1
            return DUPLICATE
        s.set(seq, True)
        s.missing -= 1
        self.reordered_total += 1
        return REORDERED

    def missing_in_window(self) -> int:
        return sum(s.missing for s in self._streams.values())

    def highest(self, sensor_id: str, boot_id: str) -> int:
        s = self._streams.get(self._key(sensor_id, boot_id))
        return -1 if s is None else s.highest

    def snapshot(self) -> dict:
        return {
            "gaps_total": self.gaps_total, "duplicates_total": self.duplicates_total,
            "reordered_total": self.reordered_total, "stale_total": self.stale_total,
            "streams": [{"key": k, "base": s.base, "highest": s.highest, "missing": s.missing,
                         "bits": base64.b64encode(bytes(s.bits)).decode("ascii")} for k, s in self._streams.items()],
        }

    def restore(self, snap: dict) -> None:
        self._streams.clear()
        for k in ("gaps_total", "duplicates_total", "reordered_total", "stale_total"):
            setattr(self, k, int(snap.get(k, 0)))
        for d in snap.get("streams", []):
            s = _Stream()
            s.base, s.highest, s.missing = int(d["base"]), int(d["highest"]), int(d["missing"])
            s.bits[:] = base64.b64decode(d["bits"])
            self._streams[d["key"]] = s
