import json
import struct

from sih_common import dga_features
from sih_datagen import synthetic
from sih_datagen.packets import Capture, TcpFlow, dns_query, dns_response
from sih_datagen.pcap import generate
from sih_datagen.scenarios import SCENARIOS
from sih_sender.normalizer import ZeekNormalizer


def test_pcap_header_and_sorted_records(tmp_path):
    import random
    cap = Capture()
    rng = random.Random(1)
    f = TcpFlow(cap, "10.10.1.10", 40000, "10.10.2.5", 502, rng)
    f.close(f.send(f.open(2_000_000), True, b"x" * 3000))
    cap.udp(1_000_000, "10.10.1.40", 5353, "10.10.0.53", 53, dns_query(7, "example.com"))
    info = cap.write(tmp_path / "t.pcap")
    data = (tmp_path / "t.pcap").read_bytes()
    assert struct.unpack("<I", data[:4])[0] == 0xA1B2C3D4
    ts, off = [], 24
    while off < len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        assert incl == orig
        ts.append(sec * 1_000_000 + usec)
        off += 16 + incl
    assert ts == sorted(ts) and len(ts) == info["packets"]


def test_dns_wire_format():
    r = dns_response(0x1234, "abc.example.org", 16, 3)
    assert r[:2] == b"\x12\x34" and r[3] & 0x0F == 3 and b"\x07example" in r


def test_scenarios_are_deterministic_and_have_ground_truth(tmp_path):
    small = ["scan", "dga", "syn_flood"]
    a = generate(tmp_path / "a", small)
    b = generate(tmp_path / "b", small)
    assert a == b
    for name in small:
        assert (tmp_path / "a" / f"{name}.pcap").read_bytes() == (tmp_path / "b" / f"{name}.pcap").read_bytes()
        m = json.loads((tmp_path / "a" / f"{name}.manifest.json").read_text())
        assert m["episodes"] and all(e["threat_class"] for e in m["episodes"])
    assert set(SCENARIOS) >= {"benign", "syn_flood", "udp_amplification", "beaconing", "dga", "dns_tunnel", "encrypted",
                              "scan", "exfiltration", "mixed", "malformed"}


def test_synthetic_batch_records_normalize(tmp_path):
    run = synthetic.batch(tmp_path, rate=50, duration=20, attacks=True, seed=3)
    assert (run / ".done").exists() and json.loads((run / "manifest.json").read_text())["capture_mode"] == "synthetic_log"
    z = ZeekNormalizer("both_directions")
    n = 0
    for log_type in ("conn", "dns"):
        for line in (run / f"{log_type}.log").read_text().splitlines():
            z.normalize(log_type, line)
            n += 1
    assert n == 1000


def test_dga_fixture_labels_are_eligible():
    import random
    rng = random.Random(5)
    table = dga_features.fit_bigram_table(["waterpower", "steelworks"])
    label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(14))
    vec, info = dga_features.extract(f"{label}.com", table)
    assert info["registrable"] == f"{label}.com" and len(vec) == dga_features.DIMENSION
