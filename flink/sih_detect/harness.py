"""In-memory stand-in for PyFlink keyed state, timers and watermarks (tests and offline replays).

Logic classes implement:
    value_states: tuple[str, ...]; map_states: tuple[str, ...]
    open() -> None
    on_event(ctx, key, element) -> iterable of (tag, obj)
    on_timer(ctx, key, ts_ms) -> iterable of (tag, obj)
where ctx provides value(name), map(name), timer(ts_ms), metric(name, n=1), watermark().
"""
from __future__ import annotations

import heapq
from collections import defaultdict


class _Value:
    def __init__(self, store: dict, key):
        self._s, self._k = store, key

    def value(self):
        return self._s.get(self._k)

    def update(self, v):
        self._s[self._k] = v

    def clear(self):
        self._s.pop(self._k, None)


class _Map:
    def __init__(self, store: dict, key):
        self._d = store.setdefault(key, {})

    def get(self, k):
        return self._d.get(k)

    def put(self, k, v):
        self._d[k] = v

    def remove(self, k):
        self._d.pop(k, None)

    def contains(self, k):
        return k in self._d

    def items(self):
        return list(self._d.items())

    def keys(self):
        return list(self._d.keys())

    def values(self):
        return list(self._d.values())

    def is_empty(self):
        return not self._d

    def clear(self):
        self._d.clear()


class _Ctx:
    def __init__(self, h: "Harness", key):
        self.h, self.key = h, key

    def value(self, name):
        return _Value(self.h.values[name], self.key)

    def map(self, name):
        return _Map(self.h.maps[name], self.key)

    def timer(self, ts_ms: int):
        entry = (int(ts_ms), repr(self.key))
        if entry not in self.h.timer_set:
            self.h.timer_set.add(entry)
            heapq.heappush(self.h.timers, (int(ts_ms), repr(self.key), self.key))

    def metric(self, name: str, n: int = 1):
        self.h.metrics[name] += n

    def watermark(self) -> int:
        return self.h.wm


class Harness:
    def __init__(self, logic, out_of_orderness_ms: int = 2000):
        self.logic = logic
        self.ooo = out_of_orderness_ms
        self.values = {n: {} for n in getattr(logic, "value_states", ())}
        self.maps = {n: {} for n in getattr(logic, "map_states", ())}
        self.timers: list = []
        self.timer_set: set = set()
        self.metrics: dict = defaultdict(int)
        self.wm = -(2 ** 62)
        self.max_ts = -(2 ** 62)
        if hasattr(logic, "open"):
            logic.open()

    def feed(self, key, element, ts_ms: int) -> list:
        out = list(self.logic.on_event(_Ctx(self, key), key, element) or [])
        self.max_ts = max(self.max_ts, ts_ms)
        out += self.advance(self.max_ts - self.ooo)
        return out

    def advance(self, watermark: int) -> list:
        out = []
        if watermark <= self.wm:
            return out
        self.wm = watermark
        while self.timers and self.timers[0][0] <= watermark:
            ts, rk, key = heapq.heappop(self.timers)
            self.timer_set.discard((ts, rk))
            out += list(self.logic.on_timer(_Ctx(self, key), key, ts) or [])
        return out

    def finish(self) -> list:
        return self.advance(2 ** 62)

    def state_entries(self) -> int:
        return sum(len(v) for v in self.values.values()) + sum(len(d) for m in self.maps.values() for d in m.values())
