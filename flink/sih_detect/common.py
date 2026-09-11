"""Small helpers shared by detectors."""
from __future__ import annotations

import hashlib
import math
from statistics import median

EVENT_FIELDS = ("obs_ms", "event_time_us", "offset_us", "received_us", "sensor_id", "run")


def ev_min(d: dict) -> dict:
    """The subset of an event/delta needed to describe first/last evidence."""
    return {k: d.get(k) for k in EVENT_FIELDS}


def bucket_up(ts_ms: int, step: int) -> int:
    return (ts_ms // step + 1) * step


def append_ids(ids: list, event_id: str, cap: int = 32) -> list:
    if event_id not in ids:
        ids.append(event_id)
    return ids[-cap:]


def robust_cv(values: list[float]) -> float | None:
    """1.4826 * MAD / median; None when undefined."""
    if len(values) < 2:
        return None
    m = median(values)
    if m <= 0:
        return None
    mad = median(abs(v - m) for v in values)
    return 1.4826 * mad / m


class Ewma:
    """Exponentially weighted mean/variance in a plain dict (picklable state)."""

    @staticmethod
    def new() -> dict:
        return {"n": 0, "mean": 0.0, "var": 0.0}

    @staticmethod
    def update(s: dict, x: float, alpha: float = 0.05) -> None:
        if s["n"] == 0:
            s["mean"], s["var"] = float(x), 0.0
        else:
            diff = x - s["mean"]
            s["mean"] += alpha * diff
            s["var"] = (1 - alpha) * (s["var"] + alpha * diff * diff)
        s["n"] += 1

    @staticmethod
    def std(s: dict) -> float:
        return math.sqrt(max(0.0, s["var"]))


def hash64(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(), "big")


class Cardinality:
    """Exact set up to 64 members, then a HyperLogLog with 256 registers (about 6.5% standard error).

    State is a plain dict so it pickles into Flink state; merge() unions sketches across buckets.
    """
    EXACT_CAP = 64
    P = 8
    M = 1 << P

    @classmethod
    def new(cls) -> dict:
        return {"set": [], "hll": None}

    @classmethod
    def add(cls, s: dict, item: str) -> None:
        if s["hll"] is None:
            if item in s["set"]:
                return
            s["set"].append(item)
            if len(s["set"]) > cls.EXACT_CAP:
                regs = bytearray(cls.M)
                for it in s["set"]:
                    cls._hll_add(regs, it)
                s["hll"], s["set"] = regs, []
        else:
            cls._hll_add(s["hll"], item)

    @classmethod
    def _hll_add(cls, regs: bytearray, item: str) -> None:
        h = hash64(item)
        idx = h >> (64 - cls.P)
        w = (h << cls.P) & ((1 << 64) - 1)
        rho = 1
        while rho <= 64 - cls.P and not (w & (1 << 63)):
            rho += 1
            w = (w << 1) & ((1 << 64) - 1)
        if rho > regs[idx]:
            regs[idx] = rho

    @classmethod
    def merge(cls, sketches: list[dict]) -> dict:
        out = cls.new()
        for s in sketches:
            if s["hll"] is None:
                for it in s["set"]:
                    cls.add(out, it)
            else:
                if out["hll"] is None:
                    regs = bytearray(cls.M)
                    for it in out["set"]:
                        cls._hll_add(regs, it)
                    out["hll"], out["set"] = regs, []
                out["hll"] = bytearray(max(a, b) for a, b in zip(out["hll"], s["hll"]))
        return out

    @classmethod
    def count(cls, s: dict) -> int:
        if s["hll"] is None:
            return len(s["set"])
        regs = s["hll"]
        m = cls.M
        alpha = 0.7213 / (1 + 1.079 / m)
        est = alpha * m * m / sum(2.0 ** -r for r in regs)
        zeros = regs.count(0)
        if est <= 2.5 * m and zeros:
            est = m * math.log(m / zeros)
        return int(round(est))

    @classmethod
    def is_estimate(cls, s: dict) -> bool:
        return s["hll"] is not None
