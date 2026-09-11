"""Zeek JSON line -> event.v1 link envelope (everything except receiver_received_at).

Absent or out-of-contract values become null with an explicit availability state. Zero is never
substituted for unavailable telemetry.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal

from sih_common import ids, timeutil
from sih_common.iputil import is_ip
from sih_common.linkframe import MAX_RECORD_BYTES, RecordTooLarge

LOG_TYPES = frozenset({"conn", "flow_update", "dns", "ssl", "weird"})
MAX_SAFE = 2 ** 53 - 1
ORIGINAL_MAX_CHARS = 4096

UID = re.compile(r"[A-Za-z0-9]{1,32}")
SERVICE = re.compile(r"[A-Za-z0-9_,.-]{1,64}")
HISTORY = re.compile(r"[A-Za-z^]{0,64}")
SSL_HISTORY = re.compile(r"[A-Za-z]{0,64}")
QTYPE_NAME = re.compile(r"[A-Za-z0-9_*-]{1,16}")
RCODE_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")
TLS_VERSION = re.compile(r"[A-Za-z0-9._ -]{1,16}")
CIPHER = re.compile(r"[A-Za-z0-9_-]{1,128}")
CURVE = re.compile(r"[A-Za-z0-9_-]{1,64}")
WEIRD_NAME_BAD = re.compile(r"[^A-Za-z0-9_./:-]")
CONN_STATES = frozenset({"S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"})
COUNTERS = ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")


class NormalizationError(Exception):
    """The record cannot be expressed as a valid event."""


@dataclass
class Normalized:
    log_type: str
    payload: dict
    availability: dict
    reasons: dict
    event_time_us: int
    emit_time_us: int  # when a live sensor would have emitted it (conn: start + duration)
    uid: str | None
    original_line: str


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> bool:
    return _is_int(v) or isinstance(v, Decimal)


def dumps(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class _Builder:
    __slots__ = ("payload", "availability", "reasons")

    def __init__(self):
        self.payload: dict = {}
        self.availability: dict = {}
        self.reasons: dict = {}

    def unavailable(self, field: str, state: str, reason: str | None) -> None:
        self.payload[field] = None
        self.availability[field] = state
        if reason:
            self.reasons[field] = reason

    def count(self, n: dict, zeek: str, field: str, maximum: int, absent_state: str, absent_reason: str) -> None:
        v = n.get(zeek)
        if v is None:
            self.unavailable(field, absent_state, absent_reason)
        elif _is_int(v) and 0 <= v <= maximum:
            self.payload[field] = v
        else:
            self.unavailable(field, "UNKNOWN", "value_out_of_contract")

    def port(self, n: dict, zeek: str, field: str) -> None:
        self.count(n, zeek, field, 65535, "MISSING", "zeek_field_absent")

    def seconds(self, n: dict, zeek: str, field: str, absent_state: str, absent_reason: str) -> None:
        v = n.get(zeek)
        if v is None:
            self.unavailable(field, absent_state, absent_reason)
        elif _is_num(v) and 0 <= v <= 31536000:
            self.payload[field] = float(v)
        else:
            self.unavailable(field, "UNKNOWN", "value_out_of_contract")

    def boolean(self, n: dict, zeek: str, field: str, absent_state: str, absent_reason: str) -> None:
        v = n.get(zeek)
        if v is None:
            self.unavailable(field, absent_state, absent_reason)
        elif isinstance(v, bool):
            self.payload[field] = v
        else:
            self.unavailable(field, "UNKNOWN", "value_out_of_contract")

    def text(self, n: dict, zeek: str, field: str, pattern, max_len: int, absent_state: str, absent_reason: str) -> None:
        v = n.get(zeek)
        if v is None:
            self.unavailable(field, absent_state, absent_reason)
        elif isinstance(v, str) and len(v) <= max_len and (pattern is None or pattern.fullmatch(v)):
            self.payload[field] = v
        else:
            self.unavailable(field, "UNKNOWN", "value_out_of_contract")


def _parse(line: str) -> dict:
    try:
        n = json.loads(line, parse_float=Decimal)
    except (ValueError, RecursionError):
        raise NormalizationError("not valid JSON") from None
    if not isinstance(n, dict):
        raise NormalizationError("record is not a JSON object")
    return n


def _ts(n: dict) -> int:
    t = n.get("ts")
    if not _is_num(t):
        raise NormalizationError("ts missing or not numeric")
    return timeutil.zeek_ts_to_us(Decimal(t))


def _required_uid(n: dict) -> str:
    u = n.get("uid")
    if not isinstance(u, str) or not UID.fullmatch(u):
        raise NormalizationError("uid missing or invalid")
    return u


def _required_ip(n: dict, field: str) -> str:
    v = n.get(field)
    if not is_ip(v):
        raise NormalizationError(f"{field} missing or not an IP literal")
    return v


def _transport(n: dict) -> str:
    p = n.get("proto")
    return p if p in ("tcp", "udp", "icmp") else "unknown_transport"


class ZeekNormalizer:
    def __init__(self, coverage: str):
        self.coverage = coverage

    def emit_time_us(self, log_type: str, line: str) -> int:
        """Cheap ordering key for replay: conn records are emitted at start + duration."""
        n = _parse(line)
        ts = _ts(n)
        if log_type == "conn":
            d = n.get("duration")
            if _is_num(d) and d >= 0:
                return ts + timeutil.zeek_ts_to_us(Decimal(d))
        return ts

    def normalize(self, log_type: str, line: str) -> Normalized:
        if log_type not in LOG_TYPES:
            raise NormalizationError(f"unsupported log type {log_type}")
        n = _parse(line)
        ts = _ts(n)
        b = _Builder()
        emit = ts
        if log_type == "conn":
            uid = self._conn_like(n, b, terminal=True)
            d = n.get("duration")
            if b.payload["duration_s"] is not None:
                emit = ts + timeutil.zeek_ts_to_us(Decimal(d))
        elif log_type == "flow_update":
            uid = self._conn_like(n, b, terminal=False)
            seq = n.get("snapshot_seq")
            if not _is_int(seq) or not 1 <= seq <= 1_000_000_000:
                raise NormalizationError("flow_update snapshot_seq missing or out of range")
            b.payload["snapshot_seq"] = seq
            iv = n.get("snapshot_interval")
            if not _is_num(iv) or not 0.1 <= iv <= 3600:
                raise NormalizationError("flow_update snapshot_interval missing or out of range")
            b.payload["snapshot_interval_s"] = float(iv)
        elif log_type == "dns":
            uid = _dns(n, b)
        elif log_type == "ssl":
            uid = _ssl(n, b)
        else:
            uid = _weird(n, b)
        return Normalized(log_type, b.payload, b.availability, b.reasons, ts, emit, uid, line)

    def envelope(self, r: Normalized, sensor_id: str, boot_id: str, sequence: int, replay_run_id: str | None,
                 replay_offset_us: int, capture_mode: str) -> bytes:
        """Serialized link envelope. Retries without the original record when too large."""
        sha = hashlib.sha256(r.original_line.encode("utf-8")).hexdigest()
        fits = len(r.original_line) <= ORIGINAL_MAX_CHARS
        env = {
            "event_schema_version": "1.0.0",
            "event_id": ids.event_id(sensor_id, boot_id, sequence, sha),
            "sensor_id": sensor_id,
            "sensor_boot_id": boot_id,
            "sequence": sequence,
            "replay_run_id": replay_run_id,
            "replay_time_offset_us": replay_offset_us,
            "log_type": r.log_type,
            "event_time": timeutil.format_us(r.event_time_us),
            "sensor_emitted_at": timeutil.format_us(timeutil.now_us()),
            "capture_mode": capture_mode,
            "observation_coverage": self.coverage,
            "original_record_sha256": sha,
            "original_record": r.original_line if fits else None,
            "original_record_truncated": not fits,
            "availability": r.availability,
            "availability_reasons": r.reasons,
            "payload": r.payload,
        }
        out = dumps(env)
        if len(out) > MAX_RECORD_BYTES and fits:
            env["original_record"] = None
            env["original_record_truncated"] = True
            out = dumps(env)
        if len(out) > MAX_RECORD_BYTES:
            raise RecordTooLarge(f"envelope {len(out)} bytes after dropping original record")
        return out

    def _conn_like(self, n: dict, b: _Builder, terminal: bool) -> str:
        uid = _required_uid(n)
        b.payload["uid"] = uid
        b.payload["src_ip"] = _required_ip(n, "id.orig_h")
        b.port(n, "id.orig_p", "src_port")
        b.payload["dst_ip"] = _required_ip(n, "id.resp_h")
        b.port(n, "id.resp_p", "dst_port")
        b.payload["proto"] = _transport(n)
        svc = n.get("service")
        if isinstance(svc, list):
            svc = ",".join(str(s) for s in svc)
        if svc is None:
            b.unavailable("service", "UNKNOWN", "no_protocol_identified")
        elif isinstance(svc, str) and SERVICE.fullmatch(svc):
            b.payload["service"] = svc
        else:
            b.unavailable("service", "UNKNOWN", "value_out_of_contract")
        b.seconds(n, "duration", "duration_s", "MISSING", "zeek_field_absent")
        for f in COUNTERS:
            b.count(n, f, f, MAX_SAFE, "MISSING", "zeek_field_absent")
        b.text(n, "history", "history", HISTORY, 64, "MISSING", "zeek_field_absent")
        if terminal:
            b.count(n, "missed_bytes", "missed_bytes", MAX_SAFE, "MISSING", "zeek_field_absent")
            cs = n.get("conn_state")
            if cs is None:
                b.unavailable("conn_state", "MISSING", "zeek_field_absent")
            elif cs in CONN_STATES:
                b.payload["conn_state"] = cs
            else:
                b.unavailable("conn_state", "UNKNOWN", "value_out_of_contract")
            b.boolean(n, "local_orig", "local_orig", "UNKNOWN", "site_networks_unconfigured")
            b.boolean(n, "local_resp", "local_resp", "UNKNOWN", "site_networks_unconfigured")
        # A zero from an unobserved direction is not evidence: it becomes UNKNOWN.
        hidden = {"originator_only": ("resp_bytes", "resp_pkts", "resp_ip_bytes"),
                  "responder_only": ("orig_bytes", "orig_pkts", "orig_ip_bytes")}.get(self.coverage, ())
        for f in hidden:
            b.availability.pop(f, None)
            b.reasons.pop(f, None)
            b.unavailable(f, "UNKNOWN", "direction_not_observed")
        return uid


def _dns(n: dict, b: _Builder) -> str:
    uid = _required_uid(n)
    b.payload["uid"] = uid
    b.payload["src_ip"] = _required_ip(n, "id.orig_h")
    b.port(n, "id.orig_p", "src_port")
    b.payload["dst_ip"] = _required_ip(n, "id.resp_h")
    b.port(n, "id.resp_p", "dst_port")
    proto = _transport(n)
    if proto not in ("udp", "tcp"):
        raise NormalizationError("dns proto must be udp or tcp")
    b.payload["proto"] = proto
    b.count(n, "trans_id", "trans_id", 65535, "MISSING", "zeek_field_absent")
    b.seconds(n, "rtt", "rtt_s", "MISSING", "no_response_observed")
    q = n.get("query")
    if not isinstance(q, str):
        b.unavailable("query", "MISSING", "zeek_field_absent")
        b.payload["query_truncated"] = False
    else:
        b.payload["query"] = q[:255]
        b.payload["query_truncated"] = len(q) > 255
    b.count(n, "qclass", "qclass", 65535, "MISSING", "zeek_field_absent")
    b.count(n, "qtype", "qtype", 65535, "MISSING", "zeek_field_absent")
    b.text(n, "qtype_name", "qtype_name", QTYPE_NAME, 16, "MISSING", "zeek_field_absent")
    b.count(n, "rcode", "rcode", 65535, "MISSING", "no_response_observed")
    b.text(n, "rcode_name", "rcode_name", RCODE_NAME, 32, "MISSING", "no_response_observed")
    for f in ("AA", "TC", "RD", "RA"):
        b.boolean(n, f, f.lower(), "MISSING", "zeek_field_absent")
    answers = n.get("answers")
    if isinstance(answers, list):
        trunc = len(answers) > 16
        out = []
        for a in answers[:16]:
            s = str(a)
            if len(s) > 255:
                s, trunc = s[:255], True
            out.append(s)
        b.payload["answers"] = out
        b.payload["answers_truncated"] = trunc
    elif b.payload["rcode"] is not None:
        b.payload["answers"] = []  # response observed with no answer records: a genuine empty list
        b.payload["answers_truncated"] = False
    else:
        b.unavailable("answers", "MISSING", "no_response_observed")
        b.payload["answers_truncated"] = False
    b.boolean(n, "rejected", "rejected", "MISSING", "zeek_field_absent")
    return uid


def _ssl(n: dict, b: _Builder) -> str:
    uid = _required_uid(n)
    b.payload["uid"] = uid
    b.payload["src_ip"] = _required_ip(n, "id.orig_h")
    b.port(n, "id.orig_p", "src_port")
    b.payload["dst_ip"] = _required_ip(n, "id.resp_h")
    b.port(n, "id.resp_p", "dst_port")
    b.text(n, "version", "version", TLS_VERSION, 16, "MISSING", "handshake_incomplete")
    b.text(n, "cipher", "cipher", CIPHER, 128, "MISSING", "handshake_incomplete")
    b.text(n, "curve", "curve", CURVE, 64, "UNKNOWN", "zeek_field_absent")
    b.text(n, "server_name", "server_name", None, 255, "MISSING", "not_sent_by_client")
    b.boolean(n, "resumed", "resumed", "MISSING", "zeek_field_absent")
    b.boolean(n, "established", "established", "MISSING", "zeek_field_absent")
    b.text(n, "next_protocol", "next_protocol", None, 64, "NOT_APPLICABLE", "alpn_not_negotiated")
    b.text(n, "ssl_history", "ssl_history", SSL_HISTORY, 64, "MISSING", "zeek_field_absent")
    b.text(n, "validation_status", "validation_status", None, 128, "UNKNOWN", "validation_not_configured")
    fps = n.get("cert_chain_fps")
    if isinstance(fps, list):
        if len(fps) <= 32:
            b.payload["cert_chain_len"] = len(fps)
        else:
            b.unavailable("cert_chain_len", "UNKNOWN", "value_out_of_contract")
    else:
        tls13 = n.get("version") == "TLSv13"
        b.unavailable("cert_chain_len", "UNKNOWN", "tls13_certificates_encrypted" if tls13 else "no_certificate_observed")
    b.boolean(n, "sni_matches_cert", "sni_matches_cert", "UNKNOWN", "zeek_field_absent")
    return uid


def _weird(n: dict, b: _Builder) -> str | None:
    u = n.get("uid")
    uid = u if isinstance(u, str) and UID.fullmatch(u) else None
    if uid:
        b.payload["uid"] = uid
    else:
        b.unavailable("uid", "NOT_APPLICABLE", "not_connection_scoped")
    for zeek, field in (("id.orig_h", "src_ip"), ("id.resp_h", "dst_ip")):
        v = n.get(zeek)
        if v is None:
            b.unavailable(field, "NOT_APPLICABLE", "not_connection_scoped")
        elif is_ip(v):
            b.payload[field] = v
        else:
            b.unavailable(field, "UNKNOWN", "value_out_of_contract")
    b.count(n, "id.orig_p", "src_port", 65535, "NOT_APPLICABLE", "not_connection_scoped")
    b.count(n, "id.resp_p", "dst_port", 65535, "NOT_APPLICABLE", "not_connection_scoped")
    name = n.get("name")
    if not isinstance(name, str) or not name:
        raise NormalizationError("weird name missing")
    b.payload["name"] = WEIRD_NAME_BAD.sub("_", name)[:128]
    addl = n.get("addl")
    if addl is None:
        b.unavailable("addl", "NOT_APPLICABLE", "no_additional_info")
    else:
        b.payload["addl"] = str(addl)[:256]
    b.boolean(n, "notice", "notice", "MISSING", "zeek_field_absent")
    b.text(n, "peer", "peer", None, 64, "MISSING", "zeek_field_absent")
    b.text(n, "source", "source", None, 64, "NOT_APPLICABLE", "zeek_field_absent")
    return uid
