"""One-way link frame codec (docs/contracts.md, "One-way link frame")."""
from __future__ import annotations

import hashlib
import hmac
import struct
import uuid
from dataclasses import dataclass

MAGIC = b"SIH1"
VERSION = 1
TYPE_EVENT = 1
TYPE_HEALTH = 2
MAX_DATAGRAM_BYTES = 1400
MAX_CHUNK_BYTES = 1200
MAX_RECORD_BYTES = 9600
MAX_FRAGMENTS = 8
HMAC_BYTES = 32

_HEAD = struct.Struct(">4sBBBBBB")  # magic, version, type, flags, fragment index, fragment count, sensor_id length
_MID = struct.Struct(">16sQIH")     # boot uuid, sequence, total record length, chunk length
_MIN_FRAME = _HEAD.size + 1 + _MID.size + HMAC_BYTES
_SID_OK = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789-")


class FrameError(Exception):
    """Rejected frame; `reason` is an invalid-event.v1 reason code."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class RecordTooLarge(Exception):
    pass


@dataclass(frozen=True)
class Frame:
    type: int
    frag_index: int
    frag_count: int
    sensor_id: str
    boot_id: str
    sequence: int
    total_length: int
    chunk: bytes


class LinkCodec:
    def __init__(self, key: bytes):
        if len(key) < 16:
            raise ValueError("link key must be at least 16 bytes")
        self._key = key

    def _mac(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def encode(self, ftype: int, sensor_id: str, boot_id: str, sequence: int, record: bytes) -> list[bytes]:
        if len(record) > MAX_RECORD_BYTES:
            raise RecordTooLarge(f"record {len(record)} bytes exceeds {MAX_RECORD_BYTES}")
        if not record:
            raise ValueError("empty record")
        sid = sensor_id.encode("ascii")
        if not 1 <= len(sid) <= 63:
            raise ValueError("sensor_id length must be 1..63")
        boot = uuid.UUID(boot_id).bytes
        count = -(-len(record) // MAX_CHUNK_BYTES)
        frames = []
        for i in range(count):
            chunk = record[i * MAX_CHUNK_BYTES:(i + 1) * MAX_CHUNK_BYTES]
            body = (_HEAD.pack(MAGIC, VERSION, ftype, 0, i, count, len(sid)) + sid
                    + _MID.pack(boot, sequence, len(record), len(chunk)) + chunk)
            frames.append(body + self._mac(body))
        return frames

    def decode(self, data: bytes) -> Frame:
        n = len(data)
        if n < _MIN_FRAME or n > MAX_DATAGRAM_BYTES:
            raise FrameError("frame_malformed", f"datagram length {n} outside bounds")
        body, tag = data[:-HMAC_BYTES], data[-HMAC_BYTES:]
        if not hmac.compare_digest(self._mac(body), tag):
            raise FrameError("frame_hmac_invalid", "HMAC mismatch")
        magic, version, ftype, _flags, idx, count, sid_len = _HEAD.unpack_from(body, 0)
        if magic != MAGIC or version != VERSION:
            raise FrameError("frame_malformed", "bad magic or version")
        if ftype not in (TYPE_EVENT, TYPE_HEALTH):
            raise FrameError("frame_malformed", f"unknown frame type {ftype}")
        if not 1 <= count <= MAX_FRAGMENTS or idx >= count:
            raise FrameError("frame_malformed", f"bad fragment {idx}/{count}")
        off = _HEAD.size
        if not 1 <= sid_len <= 63 or len(body) < off + sid_len + _MID.size:
            raise FrameError("frame_malformed", "bad sensor_id length")
        sid = body[off:off + sid_len]
        if any(b not in _SID_OK for b in sid):
            raise FrameError("frame_malformed", "sensor_id has invalid characters")
        off += sid_len
        boot, seq, total, chunk_len = _MID.unpack_from(body, off)
        chunk = body[off + _MID.size:]
        if not 1 <= total <= MAX_RECORD_BYTES or chunk_len != len(chunk) or chunk_len > MAX_CHUNK_BYTES:
            raise FrameError("frame_malformed", f"bad lengths total={total} chunk={chunk_len}")
        expected_count = -(-total // MAX_CHUNK_BYTES)
        expected_len = MAX_CHUNK_BYTES if idx < expected_count - 1 else total - (expected_count - 1) * MAX_CHUNK_BYTES
        if expected_count != count or chunk_len != expected_len:
            raise FrameError("frame_malformed", "fragment geometry inconsistent with total length")
        return Frame(ftype, idx, count, sid.decode("ascii"), str(uuid.UUID(bytes=boot)), seq, total, bytes(chunk))
