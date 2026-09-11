from __future__ import annotations

import json

import pytest

from sih_common import contracts, linkframe, timeutil
from sih_receiver import dedup as dd
from sih_receiver.core import ReceiverCore, observation_ms
from sih_receiver.publisher import Publisher
from sih_receiver.spool import TOPIC_INVALID, TOPIC_RAW, Spool
from sih_sender.normalizer import ZeekNormalizer

KEY = b"0123456789abcdef0123456789abcdef"
BOOT = "7f1c2a9e-4b61-4d7e-9a0c-5c1e2f3a4b5d"
CONN = ('{"ts":1788256800.123456,"uid":"CMb1","id.orig_h":"10.10.1.20","id.orig_p":49152,"id.resp_h":"10.10.2.5",'
        '"id.resp_p":502,"proto":"tcp","service":"modbus","duration":2.5,"orig_bytes":12,"resp_bytes":11,'
        '"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"ShADadFf","orig_pkts":6,'
        '"orig_ip_bytes":332,"resp_pkts":4,"resp_ip_bytes":223}')
OFFSET = 864_000_000_000


def envelope(seq: int, line: str = CONN) -> bytes:
    z = ZeekNormalizer("both_directions")
    return z.envelope(z.normalize("conn", line), "ot-sensor-01", BOOT, seq, "run-1", OFFSET, "pcap_replay")


def frames(seq: int, record: bytes | None = None) -> list[bytes]:
    return linkframe.LinkCodec(KEY).encode(linkframe.TYPE_EVENT, "ot-sensor-01", BOOT, seq, record or envelope(seq))


def entries(core: ReceiverCore, topic: int):
    end = core.spool.sync()
    return [e for e in core.spool.read(core.spool.first_position(), end, 10_000) if e.topic == topic]


@pytest.fixture
def core(tmp_path):
    return ReceiverCore(tmp_path / "rx", KEY, 10 * 1024 * 1024, 64 * 1024)


def test_valid_event_is_spooled_with_observation_timestamp(core):
    for f in frames(0):
        core.handle_datagram(f, timeutil.now_us())
    raw = entries(core, TOPIC_RAW)
    assert len(raw) == 1
    ev = json.loads(raw[0].value)
    assert contracts.validate("event", ev) == []
    assert "receiver_received_at" in ev
    expected = (1788256800123456 + OFFSET + 2_500_000) // 1000
    assert raw[0].ts_ms == expected == observation_ms(ev)
    assert raw[0].key == f"ot-sensor-01|{BOOT}|run-1|CMb1".encode()


def test_duplicates_are_suppressed(core):
    for _ in range(3):
        for f in frames(0):
            core.handle_datagram(f, timeutil.now_us())
    assert len(entries(core, TOPIC_RAW)) == 1
    assert core.dedup.duplicates_total == 2


def test_multi_fragment_record(core):
    long_line = CONN[:-1] + ',"vendor_note":"' + "x" * 3000 + '"}'
    fr = frames(1, envelope(1, long_line))
    assert len(fr) > 1
    for f in reversed(fr):  # arrival order does not matter
        core.handle_datagram(f, timeutil.now_us())
    assert len(entries(core, TOPIC_RAW)) == 1


def test_tampered_identity_is_quarantined(core):
    ev = json.loads(envelope(2))
    ev["event_id"] = "00000000-0000-5000-8000-000000000000"
    for f in frames(2, json.dumps(ev).encode()):
        core.handle_datagram(f, timeutil.now_us())
    assert entries(core, TOPIC_RAW) == []
    inv = [json.loads(e.value) for e in entries(core, TOPIC_INVALID)]
    assert [i["reason_code"] for i in inv] == ["schema_violation"]
    assert contracts.validate("invalid_event", inv[0]) == []


def test_bad_hmac_and_garbage_are_quarantined_without_excerpt(core):
    f = bytearray(frames(3)[0])
    f[-1] ^= 1
    core.handle_datagram(bytes(f), timeutil.now_us())
    core.handle_datagram(b"garbage", timeutil.now_us())  # shorter than any frame: malformed before HMAC
    inv = [json.loads(e.value) for e in entries(core, TOPIC_INVALID)]
    assert sorted(i["reason_code"] for i in inv) == ["frame_hmac_invalid", "frame_malformed"]
    assert all(i["raw_excerpt"] is None for i in inv)


def test_incomplete_fragments_time_out(core):
    long_line = CONN[:-1] + ',"vendor_note":"' + "x" * 3000 + '"}'
    fr = frames(4, envelope(4, long_line))
    core.handle_datagram(fr[0], 0)
    assert core.reassembler.expire(3_000_000)[0].reason == "fragment_timeout"


def test_restart_keeps_duplicate_suppression(tmp_path):
    a = ReceiverCore(tmp_path / "rx", KEY, 10 * 1024 * 1024, 64 * 1024)
    for f in frames(0):
        a.handle_datagram(f, timeutil.now_us())
    a.spool.sync()
    a.spool.close()  # crash before any dedup snapshot: the spool replay restores the window
    b = ReceiverCore(tmp_path / "rx", KEY, 10 * 1024 * 1024, 64 * 1024)
    for f in frames(0):
        b.handle_datagram(f, timeutil.now_us())
    assert len(entries(b, TOPIC_RAW)) == 1


def test_spool_limit_drops_newest(tmp_path):
    probe = ReceiverCore(tmp_path / "probe", KEY, 10 * 1024 * 1024, 64 * 1024)
    for f in frames(0):
        probe.handle_datagram(f, timeutil.now_us())
    one_record = probe.spool.total_bytes
    small = ReceiverCore(tmp_path / "rx", KEY, one_record + 50, 64 * 1024)
    for seq in range(5):
        for f in frames(seq):
            small.handle_datagram(f, timeutil.now_us())
    assert len(entries(small, TOPIC_RAW)) == 1
    assert small.dedup.check("ot-sensor-01", BOOT, 1) == dd.NEW  # dropped records were not marked


def test_dedup_window_gaps():
    w = dd.DedupWindow()
    assert w.mark("s", BOOT, 10) == dd.NEW
    w.mark("s", BOOT, 11)
    assert w.mark("s", BOOT, 11) == dd.DUPLICATE
    w.mark("s", BOOT, 15)
    assert w.missing_in_window() == 3
    assert w.mark("s", BOOT, 13) == dd.REORDERED
    w.mark("s", BOOT, 15 + dd.WINDOW)
    assert w.gaps_total == 2
    assert w.mark("s", BOOT, 12) == dd.STALE
    r = dd.DedupWindow()
    r.restore(w.snapshot())
    assert r.check("s", BOOT, 15 + dd.WINDOW) == dd.DUPLICATE


def test_spool_truncates_torn_tail(tmp_path):
    s = Spool(tmp_path / "sp", 1 << 20, 1 << 20)
    for i in range(3):
        assert s.append(TOPIC_RAW, b"k", "s", BOOT, i, 1000 + i, b"v" * 10)
    s.close()
    seg = next((tmp_path / "sp").glob("seg-*.log"))
    with open(seg, "ab") as f:
        f.write(b"\x00\x00\x00\x40partial")
    s2 = Spool(tmp_path / "sp", 1 << 20, 1 << 20)
    got = s2.read(s2.first_position(), s2.end(), 100)
    assert [e.sequence for e in got] == [0, 1, 2] and got[2].ts_ms == 1002


class FakeProducer:
    """Delivers on poll; can be told to fail the n-th produce call."""

    def __init__(self, sent: list, fail_at: int | None = None):
        self.sent, self.fail_at, self.pending, self.calls = sent, fail_at, [], 0

    def produce(self, topic, value=None, key=None, timestamp=0, on_delivery=None):
        self.calls += 1
        err = "MSG_TIMED_OUT" if self.fail_at is not None and self.calls == self.fail_at else None
        self.pending.append((err, on_delivery, (topic, key, value, timestamp)))

    def poll(self, _t=0):
        for err, cb, rec in self.pending:
            if err is None:
                self.sent.append(rec)
            cb(err, None)
        self.pending = []

    def flush(self, _t=0):
        self.poll()


def test_publisher_resends_from_cursor_after_failure(tmp_path):
    s = Spool(tmp_path / "sp", 1 << 20, 1 << 20)
    for i in range(5):
        s.append(TOPIC_RAW, b"k", "s", BOOT, i, 1000 + i, f"v{i}".encode())
    s.sync()
    sent: list = []
    pub = Publisher(s, tmp_path / "cursor", lambda: None)
    with pytest.raises(RuntimeError):
        pub.pump(FakeProducer(sent, fail_at=3), max_idle_rounds=3)
    assert [r[2] for r in sent] == [b"v0", b"v1", b"v3", b"v4"]
    assert pub.cursor == s.read(s.first_position(), s.end(), 10)[1].end  # stops before the failed record
    pub.pump(FakeProducer(sent), max_idle_rounds=3)
    assert [r[2] for r in sent][4:] == [b"v2", b"v3", b"v4"]  # resend includes already-delivered v3/v4
    assert pub.cursor == s.end()
    assert Publisher(s, tmp_path / "cursor", lambda: None).cursor == s.end()  # persisted
