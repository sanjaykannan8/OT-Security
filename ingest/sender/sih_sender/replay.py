"""Replay completed run directories (Zeek `-r` output or synthetic batches) marked with `.done`.

Records are ordered by the time a live sensor would have emitted them and paced against wall clock.
Sequence numbers are reserved per run (base + index), so a restart resumes the same run with identical
identifiers. The replay offset makes observation time (event_time + offset) track wall clock.
"""
from __future__ import annotations

import logging
import pathlib
import re
import threading
import time

from sih_common import timeutil
from sih_sender.context import SenderContext
from sih_sender.normalizer import NormalizationError
from sih_sender.tail import NAME

log = logging.getLogger("sender.replay")
RUN_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


class ReplayMode:
    def __init__(self, ctx: SenderContext):
        self.ctx = ctx
        self.root = pathlib.Path(ctx.cfg.input_dir)

    def run(self, stop: threading.Event) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        log.info("replay mode started (root=%s, speed=%s)", self.root, self.ctx.cfg.replay_speed)
        while not stop.is_set():
            run_dir = self.next_run()
            if run_dir is None:
                self.ctx.sender_state = "idle"
                self.ctx.zeek_status = "not_running"
                stop.wait(1.0)
                continue
            self.ctx.sender_state = "running"
            self.ctx.zeek_status = "finished"
            self.replay(run_dir, stop)

    def next_run(self) -> pathlib.Path | None:
        st = self.ctx.state
        if st.current_run is not None:
            p = self.root / st.current_run["run_id"]
            if p.is_dir():
                return p
            log.warning("in-progress run directory disappeared; abandoning %s", st.current_run["run_id"])
            st.mark_completed(st.current_run["run_id"])
            st.save()
        done = set(st.completed_runs)
        candidates = sorted(p for p in self.root.iterdir()
                            if p.is_dir() and RUN_ID.fullmatch(p.name) and (p / ".done").exists() and p.name not in done)
        return candidates[0] if candidates else None

    def index(self, files: list[pathlib.Path]) -> list[tuple[int, int, int, int]]:
        """(emit_us, file_index, byte_offset, byte_length) per record, sorted."""
        items = []
        limit = self.ctx.cfg.max_replay_records
        for fi, path in enumerate(files):
            log_type = NAME.fullmatch(path.name).group(1)
            with open(path, "rb") as f:
                pos = 0
                for raw in f:
                    start = pos
                    pos += len(raw)
                    line = raw.rstrip(b"\n")
                    if line.endswith(b"\r"):
                        line = line[:-1]
                    if not line or line.startswith(b"#"):
                        continue
                    try:
                        emit = self.ctx.normalizer.emit_time_us(log_type, line.decode("utf-8"))
                    except (NormalizationError, UnicodeDecodeError):
                        self.ctx.invalid_local += 1
                        continue
                    items.append((emit, fi, start, len(line)))
                    if len(items) >= limit:
                        log.warning("replay run truncated at SENDER_MAX_REPLAY_RECORDS=%d", limit)
                        items.sort()
                        return items
        items.sort()
        return items

    def replay(self, run_dir: pathlib.Path, stop: threading.Event) -> None:
        run_id = run_dir.name
        files = sorted(p for p in run_dir.iterdir() if p.is_file() and NAME.fullmatch(p.name))
        items = self.index(files)
        st = self.ctx.state
        run = st.current_run
        if run is None or run["run_id"] != run_id:
            wall_start = timeutil.now_us() + 500_000
            first = items[0][0] if items else 0
            run = {"run_id": run_id, "base_sequence": st.next_sequence, "total": len(items), "next_index": 0,
                   "wall_start_us": wall_start, "first_emit_us": first, "offset_us": wall_start - first}
            st.current_run = run
            st.next_sequence = run["base_sequence"] + run["total"]  # reserve the run's sequence range
            st.save()
            log.info("replay run started (run_id=%s, records=%d, base_sequence=%d)", run_id, len(items), run["base_sequence"])
        elif run["total"] != len(items):
            log.warning("run %s changed since it started (expected %d, found %d); replaying the indexed prefix",
                        run_id, run["total"], len(items))
        else:
            log.info("replay run resumed (run_id=%s, next_index=%d/%d)", run_id, run["next_index"], run["total"])

        handles = [open(p, "rb") for p in files]
        types = [NAME.fullmatch(p.name).group(1) for p in files]
        try:
            since_save = 0
            limit = min(run["total"], len(items))
            for i in range(run["next_index"], limit):
                if stop.is_set():
                    break
                emit, fi, off, length = items[i]
                self._pace(run, emit, stop)
                h = handles[fi]
                h.seek(off)
                line = h.read(length).decode("utf-8")
                self.ctx.send_record(types[fi], line, run["base_sequence"] + i, run_id, run["offset_us"])
                run["next_index"] = i + 1
                self.ctx.backlog_bytes = (limit - i - 1) * 400
                since_save += 1
                if since_save >= self.ctx.cfg.persist_every:
                    st.save()
                    since_save = 0
        finally:
            for h in handles:
                h.close()
        if run["next_index"] >= min(run["total"], len(items)):
            st.mark_completed(run_id)
            self.ctx.backlog_bytes = 0
            log.info("replay run completed (run_id=%s)", run_id)
        st.save()

    def _pace(self, run: dict, emit_us: int, stop: threading.Event) -> None:
        target = run["wall_start_us"] + (emit_us - run["first_emit_us"]) / self.ctx.cfg.replay_speed
        wait = (target - timeutil.now_us()) / 1e6
        if wait > 0.001:
            stop.wait(wait) if wait > 0.05 else time.sleep(wait)
