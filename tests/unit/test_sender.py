import hashlib
import json
import socket

from sih_common import contracts, ids, linkframe
from sih_sender.context import SenderContext, Settings
from sih_sender.link import LinkWriter
from sih_sender.normalizer import NormalizationError, ZeekNormalizer
from sih_sender.replay import ReplayMode
from sih_sender.state import SenderState
from sih_sender.tail import TailMode

import pytest

KEY = b"0123456789abcdef0123456789abcdef"
BOOT = "7f1c2a9e-4b61-4d7e-9a0c-5c1e2f3a4b5d"
CONN_SF = ('{"ts":1788256800.123456,"uid":"CMb1a2b3c4d5e6f7g8","id.orig_h":"10.10.1.20","id.orig_p":49152,'
           '"id.resp_h":"10.10.2.5","id.resp_p":502,"proto":"tcp","service":"modbus","duration":0.021345,'
           '"orig_bytes":12,"resp_bytes":0,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,'
           '"history":"ShADadFf","orig_pkts":6,"orig_ip_bytes":332,"resp_pkts":4,"resp_ip_bytes":223}')
CONN_S0 = ('{"ts":1788256800.5,"uid":"CS0aaaa1","id.orig_h":"10.10.1.20","id.orig_p":40001,"id.resp_h":"10.10.3.7",'
           '"id.resp_p":22,"proto":"tcp","conn_state":"S0","missed_bytes":0,"history":"S","orig_pkts":1,'
           '"orig_ip_bytes":44,"resp_pkts":0,"resp_ip_bytes":0}')
DNS_NX = ('{"ts":1788256801.0,"uid":"CDn0001","id.orig_h":"10.10.1.40","id.orig_p":53211,"id.resp_h":"10.10.0.53",'
          '"id.resp_p":53,"proto":"udp","trans_id":4242,"rtt":0.004,"query":"xjwqkzvbplrtd.com","qclass":1,"qtype":1,'
          '"qtype_name":"A","rcode":3,"rcode_name":"NXDOMAIN","AA":false,"TC":false,"RD":true,"RA":true,"Z":0,"rejected":false}')
SSL = ('{"ts":1788256802.0,"uid":"CTls0001","id.orig_h":"10.10.1.50","id.orig_p":50123,"id.resp_h":"198.51.100.20",'
       '"id.resp_p":8443,"version":"TLSv10","cipher":"TLS_RSA_WITH_AES_128_CBC_SHA","resumed":false,"established":false,'
       '"ssl_history":"Ch"}')
WEIRD = '{"ts":1788256803.0,"name":"truncated_IPv6","notice":false,"peer":"zeek"}'
FLOW = ('{"ts":1788256810.0,"uid":"CFup0001","id.orig_h":"10.10.1.30","id.orig_p":51000,"id.resp_h":"203.0.113.50",'
        '"id.resp_p":443,"proto":"tcp","service":"ssl","duration":10.0,"orig_bytes":52428800,"resp_bytes":40960,'
        '"orig_pkts":36000,"resp_pkts":12000,"orig_ip_bytes":54000000,"resp_ip_bytes":520000,"history":"ShADad",'
        '"snapshot_seq":2,"snapshot_interval":5.0}')


def full_event(log_type: str, line: str, coverage="both_directions", seq=5) -> dict:
    z = ZeekNormalizer(coverage)
    env = json.loads(z.envelope(z.normalize(log_type, line), "ot-sensor-01", BOOT, seq, "run-1", 1000, "pcap_replay"))
    env["receiver_received_at"] = "2026-09-11T10:00:00.000000Z"
    return env


@pytest.mark.parametrize("log_type,line", [("conn", CONN_SF), ("conn", CONN_S0), ("dns", DNS_NX), ("ssl", SSL),
                                           ("weird", WEIRD), ("flow_update", FLOW)])
def test_envelopes_validate_against_schema(log_type, line):
    for coverage in ("both_directions", "originator_only"):
        assert contracts.validate("event", full_event(log_type, line, coverage)) == []


def test_genuine_zero_is_available_and_absent_is_missing():
    z = ZeekNormalizer("both_directions")
    a = z.normalize("conn", CONN_SF)
    assert a.payload["resp_bytes"] == 0 and "resp_bytes" not in a.availability
    assert a.emit_time_us == 1788256800123456 + 21345
    b = z.normalize("conn", CONN_S0)
    assert b.payload["duration_s"] is None and b.availability["duration_s"] == "MISSING"
    assert b.availability["service"] == "UNKNOWN" and b.reasons["service"] == "no_protocol_identified"
    assert b.payload["orig_bytes"] is None and b.payload["resp_pkts"] == 0
    assert b.emit_time_us == b.event_time_us


def test_unobserved_direction_is_unknown_not_zero():
    n = ZeekNormalizer("originator_only").normalize("conn", CONN_SF)
    assert n.payload["resp_bytes"] is None
    assert (n.availability["resp_bytes"], n.reasons["resp_bytes"]) == ("UNKNOWN", "direction_not_observed")


def test_dns_answers_semantics():
    z = ZeekNormalizer("both_directions")
    assert z.normalize("dns", DNS_NX).payload["answers"] == []
    no_resp = json.loads(DNS_NX)
    for k in ("rtt", "rcode", "rcode_name"):
        del no_resp[k]
    n = z.normalize("dns", json.dumps(no_resp))
    assert n.payload["answers"] is None and n.reasons["answers"] == "no_response_observed"
    long_q = json.loads(DNS_NX)
    long_q["query"] = "a" * 300
    n = z.normalize("dns", json.dumps(long_q))
    assert len(n.payload["query"]) == 255 and n.payload["query_truncated"]


def test_envelope_identity_and_long_original():
    env = full_event("conn", CONN_SF)
    sha = hashlib.sha256(CONN_SF.encode()).hexdigest()
    assert env["original_record_sha256"] == sha
    assert env["event_id"] == ids.event_id("ot-sensor-01", BOOT, 5, sha)
    assert env["event_time"] == "2026-09-01T10:00:00.123456Z"
    long_line = CONN_SF[:-1] + ',"vendor_note":"' + "x" * 5000 + '"}'
    env = full_event("conn", long_line)
    assert env["original_record"] is None and env["original_record_truncated"]
    assert env["original_record_sha256"] == hashlib.sha256(long_line.encode()).hexdigest()
    assert contracts.validate("event", env) == []


def test_records_without_identity_are_rejected():
    z = ZeekNormalizer("both_directions")
    for bad in ('{"ts":1.0}', "not json", '{"ts":1.0,"uid":"C1","id.orig_h":"host.example","id.resp_h":"10.0.0.1"}'):
        with pytest.raises(NormalizationError):
            z.normalize("conn", bad)


# ------------------------------------------------------------------ tail / replay with a real UDP socket

def _ctx(tmp_path, mode, port, input_dir):
    s = Settings(sensor_id="test-sensor", mode=mode, input_dir=str(input_dir), state_dir=str(tmp_path / "state"),
                 persist_every=1, replay_speed=1000.0)
    state = SenderState.load(tmp_path / "state")
    return SenderContext(s, state, LinkWriter("127.0.0.1", port, KEY, 1, 10000.0)), s


def _drain(sock) -> set[int]:
    codec = linkframe.LinkCodec(KEY)
    seqs = set()
    while True:
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            return seqs
        f = codec.decode(data)
        if f.type == linkframe.TYPE_EVENT:
            seqs.add(f.sequence)


def _conn(i: int) -> str:
    return CONN_SF.replace("CMb1a2b3c4d5e6f7g8", f"C{i}").replace("1788256800.123456", f"1788256800.{i:06d}") + "\n"


@pytest.fixture
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.5)
    yield s
    s.close()


def test_tail_rotation_no_duplicates_no_skips(tmp_path, udp):
    logs = tmp_path / "logs"
    logs.mkdir()
    ctx, settings = _ctx(tmp_path, "tail", udp.getsockname()[1], logs)
    tail = TailMode(ctx)
    live = logs / "conn.log"
    live.write_text(_conn(1) + _conn(2) + _conn(3).strip())  # third line incomplete
    tail.pass_once()
    assert _drain(udp) == {0, 1}
    with open(live, "a") as f:
        f.write("\n" + _conn(4))
    rotated = logs / "conn.2026-09-01-10-00-00.log"
    live.rename(rotated)
    with open(rotated, "a") as f:
        f.write(_conn(5))
    live.write_text(_conn(6))
    tail.pass_once()
    tail.pass_once()
    assert _drain(udp) == {2, 3, 4, 5}
    assert ctx.state.next_sequence == 6
    ctx.state.save()
    # Restart over reloaded state: nothing is resent.
    ctx2 = SenderContext(settings, SenderState.load(tmp_path / "state"), ctx.link)
    TailMode(ctx2).pass_once()
    assert _drain(udp) == set()
    assert ctx2.state.next_sequence == 6


def test_replay_orders_by_emit_time_and_reserves_sequences(tmp_path, udp):
    runs = tmp_path / "runs"
    run = runs / "20260901T100000Z-test"
    run.mkdir(parents=True)
    (run / "conn.log").write_text(CONN_SF + "\n")        # emitted at start + 0.021345 s
    (run / "dns.log").write_text(DNS_NX + "\n")          # emitted 1 s later
    (run / "ssl.log").write_text(SSL + "\n")
    (run / ".done").touch()
    ctx, _ = _ctx(tmp_path, "replay", udp.getsockname()[1], runs)
    rm = ReplayMode(ctx)
    items = rm.index(sorted(p for p in run.iterdir() if p.suffix == ".log"))
    assert [i[0] for i in items] == sorted(i[0] for i in items)
    rm.replay(rm.next_run(), __import__("threading").Event())
    assert _drain(udp) == {0, 1, 2}
    assert ctx.state.next_sequence == 3 and ctx.state.current_run is None
    assert "20260901T100000Z-test" in ctx.state.completed_runs
    assert rm.next_run() is None
