import uuid
from decimal import Decimal

import pytest

from sih_common import ids, iputil, linkframe, timeutil

KEY = b"0123456789abcdef0123456789abcdef"
BOOT = "7f1c2a9e-4b61-4d7e-9a0c-5c1e2f3a4b5d"


def test_single_fragment_round_trip():
    codec = linkframe.LinkCodec(KEY)
    frames = codec.encode(linkframe.TYPE_EVENT, "ot-sensor-01", BOOT, 42, b'{"a":1}')
    assert len(frames) == 1
    f = codec.decode(frames[0])
    assert (f.sensor_id, f.boot_id, f.sequence, f.frag_count, f.chunk) == ("ot-sensor-01", BOOT, 42, 1, b'{"a":1}')


def test_max_record_fragments_fit_datagram_limit():
    codec = linkframe.LinkCodec(KEY)
    record = bytes(range(256)) * (linkframe.MAX_RECORD_BYTES // 256) + b"x" * (linkframe.MAX_RECORD_BYTES % 256)
    frames = codec.encode(linkframe.TYPE_EVENT, "s" * 63, BOOT, 9, record)
    assert len(frames) == linkframe.MAX_FRAGMENTS
    assert all(len(f) <= linkframe.MAX_DATAGRAM_BYTES for f in frames)
    assert b"".join(codec.decode(f).chunk for f in frames) == record


def test_tampered_and_wrong_key_fail_hmac():
    codec = linkframe.LinkCodec(KEY)
    f = bytearray(codec.encode(linkframe.TYPE_EVENT, "ot-sensor-01", BOOT, 1, b"{}")[0])
    f[45] ^= 1
    with pytest.raises(linkframe.FrameError) as e:
        codec.decode(bytes(f))
    assert e.value.reason == "frame_hmac_invalid"
    good = codec.encode(linkframe.TYPE_EVENT, "ot-sensor-01", BOOT, 1, b"{}")[0]
    with pytest.raises(linkframe.FrameError) as e:
        linkframe.LinkCodec(b"f" * 32).decode(good)
    assert e.value.reason == "frame_hmac_invalid"


def test_oversize_and_short_inputs():
    codec = linkframe.LinkCodec(KEY)
    with pytest.raises(linkframe.RecordTooLarge):
        codec.encode(linkframe.TYPE_EVENT, "ot-sensor-01", BOOT, 1, b"x" * (linkframe.MAX_RECORD_BYTES + 1))
    with pytest.raises(linkframe.FrameError) as e:
        codec.decode(b"\x00" * 20)
    assert e.value.reason == "frame_malformed"


def test_timestamps():
    assert timeutil.format_us(0) == "1970-01-01T00:00:00.000000Z"
    assert timeutil.format_us(1788256800123456) == "2026-09-01T10:00:00.123456Z"
    assert timeutil.parse_us("2026-09-01T10:00:00.1Z") == 1788256800100000
    assert timeutil.parse_us("2026-09-01T10:00:00Z") == 1788256800000000
    for bad in ("2026-09-01T15:30:00.000000+05:30", "2026-09-01 10:00:00Z", "2026-09-01T10:00:00.Z"):
        with pytest.raises(ValueError):
            timeutil.parse_us(bad)
    assert timeutil.zeek_ts_to_us(Decimal("1.0000005")) == 1_000_001
    assert timeutil.zeek_ts_to_us(Decimal("1.0000004")) == 1_000_000


def test_ids_are_uuid5_over_joined_parts():
    assert ids.derived_id("event", "a", None, 3) == str(uuid.uuid5(ids.NAMESPACES["event"], "a||3"))
    assert ids.event_id("s", BOOT, 1, "ab") == str(uuid.uuid5(ids.NAMESPACES["event"], f"s|{BOOT}|1|ab"))


def test_ip_literals_never_resolve():
    assert iputil.is_ip("10.10.1.20") and iputil.is_ip("2001:db8::1")
    for bad in ("10.0.0.256", "01.2.3.4", "example.com", "fe80::1%eth0", "cafe", None, 7):
        assert not iputil.is_ip(bad)
    nets = iputil.NetSet(["10.0.0.0/8", "fd00::/8"])
    assert nets.contains("10.1.2.3") and nets.contains("fd00::1") and not nets.contains("8.8.8.8")
