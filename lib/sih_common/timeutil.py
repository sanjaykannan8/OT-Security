"""Canonical timestamps: UTC, exactly six fractional digits on output; 0-6 digits accepted on input."""
from __future__ import annotations

import datetime as _dt
import re
import time
from decimal import ROUND_HALF_UP, Decimal

_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
_TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?Z")


def now_us() -> int:
    return time.time_ns() // 1000


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def format_us(epoch_us: int) -> str:
    dt = _EPOCH + _dt.timedelta(microseconds=epoch_us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


def format_ms(epoch_ms: int) -> str:
    return format_us(epoch_ms * 1000)


def parse_us(text: str) -> int:
    """Strict parse; raises ValueError for anything but YYYY-MM-DDTHH:MM:SS[.f{1,6}]Z."""
    m = _TS.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise ValueError(f"timestamp not in canonical form: {str(text)[:40]!r}")
    dt = _dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=_dt.timezone.utc)
    frac = int((m.group(2) or "0").ljust(6, "0"))
    return int((dt - _EPOCH).total_seconds()) * 1_000_000 + frac


def zeek_ts_to_us(ts: Decimal | int | str) -> int:
    """Zeek decimal seconds -> integer microseconds, rounded half-up (never via binary float)."""
    d = ts if isinstance(ts, Decimal) else Decimal(str(ts))
    return int((d * 1_000_000).quantize(Decimal(1), rounding=ROUND_HALF_UP))
