"""Durable sender state: boot id, next sequence, tail offsets and replay progress.

Persisted atomically. A restart re-reads from the last persisted position and re-assigns the same
sequence numbers, so any resent records are exact duplicates that the receiver window and event_id
deduplication remove.
"""
from __future__ import annotations

import json
import pathlib
import threading
import uuid

from sih_common.env import atomic_write

MAX_COMPLETED_RUNS = 1000


class SenderState:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.boot_id = str(uuid.uuid4())
        self.next_sequence = 0
        self.health_seq = 0
        self.tail_files: dict[str, dict] = {}   # key -> {path, offset, fingerprint}
        self.completed_runs: list[str] = []
        self.current_run: dict | None = None     # {run_id, base_sequence, total, next_index, wall_start_us, first_emit_us, offset_us}
        self._lock = threading.Lock()

    @classmethod
    def load(cls, state_dir: pathlib.Path) -> "SenderState":
        state_dir = pathlib.Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        s = cls(state_dir / "sender-state.json")
        if not s.path.exists():
            s.save()
            return s
        d = json.loads(s.path.read_text(encoding="utf-8"))
        s.boot_id = d["sensor_boot_id"]
        s.next_sequence = int(d["next_sequence"])
        s.health_seq = int(d.get("health_seq", 0))
        s.tail_files = {f["key"]: {"path": f["path"], "offset": int(f["offset"]), "fingerprint": f["fingerprint"]}
                        for f in d.get("tail_files", [])}
        s.completed_runs = list(d.get("completed_runs", []))
        s.current_run = d.get("current_run")
        return s

    def save(self) -> None:
        with self._lock:
            doc = {
                "state_version": 1,
                "sensor_boot_id": self.boot_id,
                "next_sequence": self.next_sequence,
                "health_seq": self.health_seq,
                "tail_files": [dict(key=k, **v) for k, v in list(self.tail_files.items())],
                "completed_runs": self.completed_runs[-MAX_COMPLETED_RUNS:],
                "current_run": self.current_run,
            }
            atomic_write(self.path, json.dumps(doc, indent=2).encode("utf-8"))

    def mark_completed(self, run_id: str) -> None:
        with self._lock:
            self.completed_runs.append(run_id)
            del self.completed_runs[:-MAX_COMPLETED_RUNS]
            self.current_run = None

    def next_health_seq(self) -> int:
        with self._lock:
            s = self.health_seq
            self.health_seq += 1
            return s
