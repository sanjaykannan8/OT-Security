"""Follow Zeek-style JSON logs in a directory, safely across rotation.

Files are tracked by (device, inode) plus a hash of their first bytes: a rename (rotation) continues from
the persisted offset, and a new file under the old name starts at zero. Only complete lines are consumed.
"""
from __future__ import annotations

import hashlib
import logging
import pathlib
import re
import threading

from sih_sender.context import SenderContext

log = logging.getLogger("sender.tail")

NAME = re.compile(r"(conn|flow_update|dns|ssl|weird)(\..+)?\.log")
FINGERPRINT_BYTES = 256
MAX_LINES_PER_FILE_PASS = 500
MAX_TRACKED_FILES = 1000
MAX_LINE_BYTES = 1 << 20


def fingerprint(path: pathlib.Path, n: int) -> str | None:
    """Hash of exactly the first n bytes, tagged with n."""
    try:
        with open(path, "rb") as f:
            data = f.read(n)
    except OSError:
        return None
    if len(data) != n:
        return None
    return hashlib.sha256(data).hexdigest()[:32] + f":{n}"


def _same_prefix(path: pathlib.Path, size: int, stored: str) -> bool:
    try:
        n = int(stored.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return False
    return size >= n and fingerprint(path, n) == stored


class TailMode:
    def __init__(self, ctx: SenderContext):
        self.ctx = ctx
        self.dir = pathlib.Path(ctx.cfg.input_dir)
        self._since_save = 0

    def run(self, stop: threading.Event) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        log.info("tail mode started (dir=%s, next_sequence=%d)", self.dir, self.ctx.state.next_sequence)
        while not stop.is_set():
            if not self.pass_once():
                if self._since_save:
                    self.ctx.state.save()
                    self._since_save = 0
                stop.wait(0.2)
        self.ctx.state.save()

    def pass_once(self) -> bool:
        files = sorted(p for p in self.dir.iterdir() if NAME.fullmatch(p.name) and p.is_file())
        tracked = self.ctx.state.tail_files
        seen, lag, progressed = set(), 0, False
        for p in files:
            try:
                st = p.stat()
            except FileNotFoundError:
                continue  # rotated away between listing and stat
            key = f"{st.st_dev}:{st.st_ino}"
            seen.add(key)
            size = st.st_size
            if size == 0:
                continue
            tf = tracked.get(key)
            if tf is not None and (size < tf["offset"] or not _same_prefix(p, size, tf["fingerprint"])):
                log.warning("tracked file was replaced or truncated; restarting from zero (%s)", p.name)
                tf = None
            fp = fingerprint(p, min(size, FINGERPRINT_BYTES))
            if fp is None:
                continue
            if tf is None:
                tf = {"offset": 0}
                tracked[key] = tf
            tf["path"] = str(p)
            tf["fingerprint"] = fp
            if size > tf["offset"]:
                progressed |= self._read_lines(p, NAME.fullmatch(p.name).group(1), tf)
            lag += max(0, size - tf["offset"])
        for key in [k for k in tracked if k not in seen]:
            del tracked[key]
        while len(tracked) > MAX_TRACKED_FILES:
            del tracked[next(iter(tracked))]
        self.ctx.tail_lag_bytes = lag
        self.ctx.backlog_bytes = lag
        self.ctx.files_tracked = len(tracked)
        self.ctx.sender_state = "degraded" if lag > self.ctx.cfg.spool_max_bytes else ("running" if progressed else "idle")
        return progressed

    def _read_lines(self, path: pathlib.Path, log_type: str, tf: dict) -> bool:
        lines = 0
        with open(path, "rb") as f:
            f.seek(tf["offset"])
            pos = tf["offset"]
            buf = b""
            skipping = False
            while lines < MAX_LINES_PER_FILE_PASS:
                chunk = f.read(65536)
                if not chunk:
                    break
                buf += chunk
                while lines < MAX_LINES_PER_FILE_PASS:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        if len(buf) > MAX_LINE_BYTES:
                            # Oversized line: discard what we have and skip to its newline.
                            pos += len(buf)
                            buf = b""
                            if not skipping:
                                self.ctx.rejected_oversize += 1
                            skipping = True
                        break
                    line, buf = buf[:nl], buf[nl + 1:]
                    pos += nl + 1
                    if skipping:
                        skipping = False
                    else:
                        self._handle(log_type, line)
                        lines += 1
                    tf["offset"] = pos
                if skipping:
                    tf["offset"] = pos
        # An incomplete trailing line stays unread until its newline arrives.
        return lines > 0

    def _handle(self, log_type: str, raw: bytes) -> None:
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw or raw.startswith(b"#"):
            return
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            self.ctx.invalid_local += 1
            return
        seq = self.ctx.state.next_sequence
        self.ctx.send_record(log_type, line, seq, None, 0)
        self.ctx.state.next_sequence = seq + 1
        self._since_save += 1
        if self._since_save >= self.ctx.cfg.persist_every:
            self.ctx.state.save()
            self._since_save = 0
