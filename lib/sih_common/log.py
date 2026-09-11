"""One-line JSON logging to stderr. Never log event payload contents."""
from __future__ import annotations

import json
import logging
import sys

from sih_common import timeutil


class _JsonFormatter(logging.Formatter):
    def __init__(self, component: str):
        super().__init__()
        self.component = component

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": timeutil.format_us(int(record.created * 1_000_000)),
            "level": record.levelname,
            "component": self.component,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "kv", None)
        if isinstance(extra, dict):
            out.update(extra)
        if record.exc_info:
            out["error"] = self.formatException(record.exc_info)[-2000:]
        return json.dumps(out, default=str, ensure_ascii=True)


def setup(component: str, level: str = "INFO") -> logging.Logger:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter(component))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for noisy in ("kafka", "urllib3", "httpx", "uvicorn.access"):
        logging.getLogger(noisy).setLevel("WARNING")
    return logging.getLogger(component)


def kv(**fields) -> dict:
    """Usage: log.info("message", extra=kv(sensor_id=...))."""
    return {"kv": fields}
