"""Durable, bounded, append-only spool of accepted records awaiting publication.

Segment files hold length-prefixed records with CRC32. A torn record at the tail of the newest segment
(crash during write) is truncated on open. Appends are refused once total bytes reach the limit.

Record: u32 body_len | body | u32 crc32(body)
Body:   u8 topic | u16 key_len | key | u8 sensor_len | sensor | 16 boot | i64 seq | i64 ts_ms | u32 value_len | value
Positions are (segment_id, byte_offset) tuples and compare naturally.
"""
from __future__ import annotations

import logging
import os
import pathlib
import struct
import threading
import uuid
import zlib
from dataclasses import dataclass

from sih_common.env import atomic_write

log = logging.getLogger("receiver.spool")

TOPIC_RAW, TOPIC_INVALID, TOPIC_HEALTH = 1, 2, 3
_U32 = struct.Struct(">I")
_HEAD = struct.Struct(">BH")
_TAIL = struct.Struct(">qqI")
_ZERO_UUID = bytes(16)

Position = tuple  # (segment_id, offset)


@dataclass
class Entry:
    topic: int
    key: bytes
    sensor_id: str | None
    boot_id: str | None
    sequence: int
    ts_ms: int
    value: bytes
    start: Position
    end: Position


def _parse_body(body: bytes, start: Position, end: Position) -> Entry:
    topic, klen = _HEAD.unpack_from(body, 0)
    off = _HEAD.size
    key = body[off:off + klen]
    off += klen
    slen = body[off]
    off += 1
    sid = body[off:off + slen].decode("ascii") if slen else None
    off += slen
    boot = body[off:off + 16]
    off += 16
    seq, ts_ms, vlen = _TAIL.unpack_from(body, off)
    off += _TAIL.size
    value = body[off:off + vlen]
    return Entry(topic, key, sid, str(uuid.UUID(bytes=boot)) if sid else None, seq, ts_ms, value, start, end)


class Spool:
    def __init__(self, directory: pathlib.Path, max_bytes: int, segment_bytes: int = 64 * 1024 * 1024):
        self.dir = pathlib.Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.segment_bytes = segment_bytes
        self._lock = threading.Lock()
        self._sizes: dict[int, int] = {}
        for p in self.dir.glob("seg-*.log"):
            self._sizes[int(p.name[4:20])] = p.stat().st_size
        self._fh = None
        if not self._sizes:
            self._open_segment(0)
        else:
            self._active = max(self._sizes)
            path = self._path(self._active)
            valid = self._valid_prefix(path)
            if valid < self._sizes[self._active]:
                log.warning("truncating torn spool tail (segment=%d valid=%d size=%d)", self._active, valid, self._sizes[self._active])
                with open(path, "r+b") as f:
                    f.truncate(valid)
                    os.fsync(f.fileno())
            self._sizes[self._active] = valid
            self._fh = open(path, "ab", buffering=0)
        self._total = sum(self._sizes.values())
        self._dirty = False
        self._synced = (self._active, self._sizes[self._active])

    def _path(self, seg: int) -> pathlib.Path:
        return self.dir / f"seg-{seg:016d}.log"

    def _open_segment(self, seg: int) -> None:
        if self._fh is not None:
            os.fsync(self._fh.fileno())
            self._fh.close()
        self._active = seg
        self._fh = open(self._path(seg), "ab", buffering=0)
        self._sizes.setdefault(seg, 0)

    @property
    def total_bytes(self) -> int:
        return self._total

    def append(self, topic: int, key: bytes, sensor_id: str | None, boot_id: str | None, seq: int,
               ts_ms: int, value: bytes) -> bool:
        """Append one record; returns False (writing nothing) when the spool is at its byte limit."""
        sid = (sensor_id or "").encode("ascii")
        boot = uuid.UUID(boot_id).bytes if boot_id else _ZERO_UUID
        body = b"".join((_HEAD.pack(topic, len(key)), key, bytes((len(sid),)), sid, boot,
                         _TAIL.pack(seq, ts_ms, len(value)), value))
        rec = _U32.pack(len(body)) + body + _U32.pack(zlib.crc32(body))
        with self._lock:
            if self._total + len(rec) > self.max_bytes:
                return False
            if self._sizes[self._active] > 0 and self._sizes[self._active] + len(rec) > self.segment_bytes:
                self._open_segment(self._active + 1)
            self._fh.write(rec)
            self._sizes[self._active] += len(rec)
            self._total += len(rec)
            self._dirty = True
        return True

    def sync(self) -> Position:
        """Group commit: fsync if anything was appended; returns the durable end position."""
        with self._lock:
            if self._dirty:
                os.fsync(self._fh.fileno())
                self._dirty = False
            self._synced = (self._active, self._sizes[self._active])
            return self._synced

    def synced_end(self) -> Position:
        return self._synced

    def end(self) -> Position:
        with self._lock:
            return (self._active, self._sizes[self._active])

    def first_position(self) -> Position:
        with self._lock:
            return (min(self._sizes), 0)

    def read(self, start: Position, limit: Position, max_entries: int) -> list[Entry]:
        out: list[Entry] = []
        seg, off = start
        while len(out) < max_entries and (seg, off) < limit:
            with self._lock:
                size = self._sizes.get(seg)
                later = [s for s in self._sizes if s > seg]
            if size is None:
                if not later:
                    break
                seg, off = min(later), 0
                continue
            seg_end = limit[1] if seg == limit[0] else size
            if off >= seg_end:
                if seg >= limit[0] or not later:
                    break
                seg, off = min(later), 0
                continue
            with open(self._path(seg), "rb") as f:
                f.seek(off)
                while len(out) < max_entries and off < seg_end:
                    head = f.read(4)
                    (blen,) = _U32.unpack(head)
                    body = f.read(blen)
                    (crc,) = _U32.unpack(f.read(4))
                    if zlib.crc32(body) != crc:
                        raise IOError(f"spool CRC mismatch at {seg}:{off}")
                    end = off + 8 + blen
                    out.append(_parse_body(body, (seg, off), (seg, end)))
                    off = end
        return out

    def release(self, acked: Position) -> None:
        """Delete segments entirely before `acked` (never the active one)."""
        with self._lock:
            for seg in sorted(self._sizes):
                if seg >= acked[0] or seg == self._active:
                    break
                self._total -= self._sizes.pop(seg)
                try:
                    self._path(seg).unlink()
                except FileNotFoundError:
                    pass

    @staticmethod
    def _valid_prefix(path: pathlib.Path) -> int:
        pos = 0
        with open(path, "rb") as f:
            data = f.read()
        while pos + 8 <= len(data):
            (blen,) = _U32.unpack_from(data, pos)
            if blen <= 0 or pos + 8 + blen > len(data):
                break
            body = data[pos + 4:pos + 4 + blen]
            (crc,) = _U32.unpack_from(data, pos + 4 + blen)
            if zlib.crc32(body) != crc:
                break
            pos += 8 + blen
        return pos

    def close(self) -> None:
        with self._lock:
            os.fsync(self._fh.fileno())
            self._fh.close()


def write_position(path: pathlib.Path, pos: Position) -> None:
    atomic_write(path, f"{pos[0]}:{pos[1]}".encode("ascii"))


def read_position(path: pathlib.Path) -> Position | None:
    try:
        seg, off = pathlib.Path(path).read_text().strip().split(":")
        return (int(seg), int(off))
    except FileNotFoundError:
        return None
