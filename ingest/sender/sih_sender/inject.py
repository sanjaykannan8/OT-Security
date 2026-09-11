"""Failure-test tool: send deliberately bad frames toward the receiver.

    python -m sih_sender.inject <case> [count]
    cases: bad-hmac, malformed, invalid-json, schema-violation, unsupported-version, gap, duplicate

Uses sensor_id "inject-test" so injected records never mix with fixture sensors.
"""
from __future__ import annotations

import socket
import sys
import uuid

from sih_common import env
from sih_common.linkframe import TYPE_EVENT, LinkCodec

SENSOR = "inject-test"


def frames_for(case: str, codec: LinkCodec, boot: str, i: int) -> list[bytes]:
    if case == "bad-hmac":
        f = bytearray(codec.encode(TYPE_EVENT, SENSOR, boot, i, b"{}")[0])
        f[-1] ^= 0x55
        return [bytes(f)]
    if case == "malformed":
        return [b"not a frame at all, just bytes long enough to pass the minimum length check" * 2]
    if case == "invalid-json":
        return codec.encode(TYPE_EVENT, SENSOR, boot, i, b'{"event_schema_version":')
    if case == "schema-violation":
        return codec.encode(TYPE_EVENT, SENSOR, boot, i, b'{"event_schema_version":"1.0.0","log_type":"conn","payload":{}}')
    if case == "unsupported-version":
        return codec.encode(TYPE_EVENT, SENSOR, boot, i, b'{"event_schema_version":"9.0.0"}')
    if case == "gap":
        return codec.encode(TYPE_EVENT, SENSOR, boot, 0 if i == 0 else 100_000 * i, b'{"event_schema_version":"1.0.0"}')
    if case == "duplicate":
        return codec.encode(TYPE_EVENT, SENSOR, boot, 7, b'{"event_schema_version":"1.0.0"}')
    raise SystemExit(f"unknown case {case}")


def main(argv: list[str]) -> None:
    case = argv[1] if len(argv) > 1 else "malformed"
    count = int(argv[2]) if len(argv) > 2 else 1
    codec = LinkCodec(env.secret_file("LINK_KEY_FILE"))
    target = (env.env_str("LINK_TARGET_HOST", "receiver"), env.env_int("LINK_TARGET_PORT", 9500))
    boot = str(uuid.uuid5(uuid.NAMESPACE_OID, f"inject-{case}"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for i in range(count):
            for f in frames_for(case, codec, boot, i):
                s.sendto(f, target)
    print(f"sent {count} '{case}' injection(s) to {target[0]}:{target[1]}")


if __name__ == "__main__":
    main(sys.argv)
