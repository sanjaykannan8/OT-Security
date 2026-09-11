"""Detector behaviour through the in-memory harness (same logic classes the PyFlink job runs)."""
import random

import pytest

from sih_common import contracts, ids
from sih_detect.beacon import BeaconLogic
from sih_detect.config import DetectConfig
from sih_detect.ddos import DdosLogic
from sih_detect.dns import DgaBurstLogic, DnsDomainLogic, DnsScorer
from sih_detect.encrypted import EncryptedLogic
from sih_detect.exfil import ExfilLogic
from sih_detect.flowdelta import FlowDeltaLogic
from sih_detect.harness import Harness
from sih_detect.incidents import IncidentLogic
from sih_detect.reference import AssetInventory
from sih_detect.scan import ScanLogic

CFG = DetectConfig(model_root="/nonexistent-models")
INV = AssetInventory.load(__import__("pathlib").Path(__file__).resolve().parents[2] / "data/fixtures/asset-inventory.json")
T0 = 1_788_256_800_000  # ms
BOOT = "7f1c2a9e-4b61-4d7e-9a0c-5c1e2f3a4b5d"
_uid = iter(range(1, 10 ** 9))


def conn(src, dst, dport, t_ms, proto="tcp", state="SF", ob=100, rb=100, dur=0.01, sport=40000, cov="both_directions",
         log_type="conn", seq=None, uid=None):
    uid = uid or f"C{next(_uid)}"
    et = (t_ms - (int((dur or 0) * 1000) if log_type == "conn" else 0)) * 1000
    p = {"uid": uid, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "proto": proto,
         "service": None, "duration_s": dur, "orig_bytes": ob, "resp_bytes": rb, "orig_pkts": 1, "resp_pkts": 1,
         "orig_ip_bytes": ob, "resp_ip_bytes": rb, "history": "S", "conn_state": state if log_type == "conn" else None}
    if log_type == "flow_update":
        p["snapshot_seq"] = seq
        et = t_ms * 1000
    return {"event_id": ids.derived_id("event", uid, t_ms, seq), "sensor_id": "ot-sensor-01", "boot": BOOT, "run": "r1",
            "offset_us": 0, "log_type": log_type, "event_time_us": et, "obs_ms": t_ms, "received_us": t_ms * 1000 + 500,
            "coverage": cov, "p": p, "a": {}}


def deltas(events):
    h = Harness(FlowDeltaLogic(CFG))
    out = []
    for ev in events:
        key = f"{ev['sensor_id']}|{ev['boot']}|{ev['run']}|{ev['p']['uid']}"
        out += [o for tag, o in h.feed(key, ev, ev["obs_ms"]) if tag == "out"]
    return out, h


def run(logic, items, key_fn):
    h = Harness(logic)
    outs = []
    for it in items:
        outs += h.feed(key_fn(it), it, it["obs_ms"])
    outs += h.finish()
    findings = [o for t, o in outs if t == "out"]
    features = [o for t, o in outs if t == "feature"]
    for fr in features:
        assert contracts.validate("feature", fr) == [], contracts.validate("feature", fr)
    return findings, features, h


def alerts_for(findings):
    """Route findings through the incident correlator and validate every alert."""
    h = Harness(IncidentLogic(CFG))
    out = []
    for f in sorted(findings, key=lambda f: f["obs_ms"]):
        out += [o for t, o in h.feed(f"{f['threat_class']}|{f['entity_type']}|{f['entity_key']}", f, f["obs_ms"]) if t == "out"]
    out += [o for t, o in h.finish() if t == "out"]
    for a in out:
        assert contracts.validate("alert", a) == [], contracts.validate("alert", a)
    return out


# ------------------------------------------------------------------ flow deltas

def test_flow_deltas_count_once():
    uid = "Clong1"
    evs = [conn("10.10.1.30", "203.0.113.50", 443, T0 + 5000, log_type="flow_update", seq=1, ob=1000, rb=10, dur=5, uid=uid),
           conn("10.10.1.30", "203.0.113.50", 443, T0 + 5000, log_type="flow_update", seq=1, ob=1000, rb=10, dur=5, uid=uid),
           conn("10.10.1.30", "203.0.113.50", 443, T0 + 10000, log_type="flow_update", seq=2, ob=900, rb=30, dur=10, uid=uid),
           conn("10.10.1.30", "203.0.113.50", 443, T0 + 12000, ob=5000, rb=40, dur=12, uid=uid),
           conn("10.10.1.30", "203.0.113.50", 443, T0 + 13000, log_type="flow_update", seq=3, ob=6000, rb=50, dur=13, uid=uid)]
    ds, h = deltas(evs)
    assert [d["new_flow"] for d in ds] == [True, False, False]
    assert sum(d["d"]["orig_bytes"] for d in ds) == 5000  # 1000 + 0 (regression) + 4000
    assert h.metrics["flow_duplicate_snapshot"] == 1
    assert h.metrics["flow_counter_regression"] == 1
    assert h.metrics["flow_late_after_terminal"] == 1
    h.finish()
    assert h.state_entries() == 0


# ------------------------------------------------------------------ scan

def test_horizontal_scan_alerts_and_expires():
    evs = [conn("10.10.1.99", f"10.10.2.{i}", 502, T0 + i * 50, state="S0", ob=0, rb=0, dur=None) for i in range(1, 41)]
    ds, _ = deltas(evs)
    findings, features, h = run(ScanLogic(CFG, INV), ds, lambda d: d["src"])
    assert findings and findings[0]["subtype"] == "horizontal_scan"
    assert findings[0]["severity"] in ("medium", "high")
    assert findings[0]["observed"]["failed_ratio"] == 1.0
    assert features
    assert h.state_entries() == 0  # expired after the horizon
    alerts = alerts_for(findings)
    assert alerts[0]["status"] == "new" and alerts[-1]["status"] == "resolved"


def test_authorized_scanner_is_info_and_pairs_are_capped():
    cfg = DetectConfig(scan_pair_cap=100)
    evs = [conn("10.10.9.200", f"10.10.{i // 250}.{i % 250}", 502, T0 + i, state="REJ", dur=None) for i in range(500)]
    ds, _ = deltas(evs)
    h = Harness(ScanLogic(cfg, INV))
    outs = []
    for d in ds:
        outs += h.feed(d["src"], d, d["obs_ms"])
    findings = [o for t, o in outs if t == "out"]
    assert findings and all(f["severity"] == "info" for f in findings)
    assert h.metrics["scan_pair_cap_reached"] == 400
    assert len(h.maps["pairs"]["10.10.9.200"]) == 100  # bounded
    assert h.values["meta"]["10.10.9.200"]["capped"] is True
    h.finish()
    assert h.state_entries() == 0


def test_benign_polling_is_not_a_scan():
    evs = [conn("10.10.1.10", f"10.10.2.{5 + i % 3}", 502, T0 + i * 1000) for i in range(300)]
    ds, _ = deltas(evs)
    findings, _, _ = run(ScanLogic(CFG, INV), ds, lambda d: d["src"])
    assert findings == []


# ------------------------------------------------------------------ floods

def test_spoofed_source_like_syn_flood():
    rng = random.Random(1)
    evs = [conn(f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}", "10.20.0.80", 80, T0 + i * 2, state="S0", ob=0, rb=0,
                dur=None, sport=rng.randint(1024, 65535)) for i in range(1500)]
    ds, _ = deltas(evs)
    findings, _, _ = run(DdosLogic(CFG, INV), ds, lambda d: d["dst"])
    # Early alert on SYN evidence, refined once enough distinct sources are observed.
    assert findings[0]["subtype"] == "syn_flood"
    spoofed = [f for f in findings if f["subtype"] == "spoofed_source_like_flood"]
    assert spoofed and "does not prove" in spoofed[0]["explanation"]
    assert "distinct_sources_5s" in spoofed[-1]["capped"]  # HLL estimate, flagged as such
    alerts = alerts_for(findings)
    assert [a["subtype"] for a in alerts[:2]] == ["syn_flood", "spoofed_source_like_flood"]
    assert alerts[1]["status"] == "updated"


def test_syn_flood_from_few_sources():
    evs = [conn(f"203.0.113.{i % 5 + 1}", "10.20.0.80", 443, T0 + i * 3, state="S0", ob=0, rb=0, dur=None, sport=10000 + i)
           for i in range(400)]
    ds, _ = deltas(evs)
    findings, _, _ = run(DdosLogic(CFG, INV), ds, lambda d: d["dst"])
    assert findings[0]["subtype"] == "syn_flood"


def test_udp_amplification_like():
    evs = [conn(f"192.0.2.{i % 60 + 1}", "10.20.0.80", 50000 + i, T0 + i * 5, proto="udp", ob=30000, rb=0, sport=123)
           for i in range(150)]
    ds, _ = deltas(evs)
    findings, _, _ = run(DdosLogic(CFG, INV), ds, lambda d: d["dst"])
    assert findings[0]["subtype"] == "udp_amplification_like"


# ------------------------------------------------------------------ beaconing

def test_external_beacon_detected_known_polling_suppressed():
    rng = random.Random(2)
    beacon = [conn("10.10.1.40", "203.0.113.10", 443, T0 + i * 60_000 + rng.randint(-800, 800), ob=512) for i in range(14)]
    polling = [conn("10.10.3.10", "10.10.2.8", 20000, T0 + i * 10_000) for i in range(40)]
    ds, _ = deltas(beacon + polling)
    ds.sort(key=lambda d: d["obs_ms"])
    findings, _, h = run(BeaconLogic(CFG, INV), ds, lambda d: f"{d['src']}|{d['dst']}|{d['dport']}|{d['proto']}")
    assert {f["entity_key"] for f in findings} == {"10.10.1.40|203.0.113.10|443|tcp"}
    assert findings[0]["severity"] in ("medium", "high")
    assert h.metrics["beacon_suppressed_known_periodic"] > 0


# ------------------------------------------------------------------ DNS

def dns_ev(src, query, t_ms, rcode="NOERROR", qtype="A"):
    uid = f"D{next(_uid)}"
    return {"event_id": ids.derived_id("event", uid), "sensor_id": "ot-sensor-01", "boot": BOOT, "run": "r1",
            "offset_us": 0, "log_type": "dns", "event_time_us": t_ms * 1000, "obs_ms": t_ms, "received_us": t_ms * 1000 + 500,
            "coverage": "both_directions",
            "p": {"uid": uid, "src_ip": src, "dst_ip": "10.10.0.53", "query": query, "rcode_name": rcode, "qtype_name": qtype},
            "a": {}}


@pytest.fixture(scope="module")
def rules_only_scorer():
    s = DnsScorer(CFG, INV)
    s.open()
    assert not s.model.active
    return s


def test_dns_tunnel_like(rules_only_scorer):
    rng = random.Random(3)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    obs = [rules_only_scorer.observe(dns_ev("10.10.1.50", "".join(rng.choice(alphabet) for _ in range(40)) + ".t.exfil-example.org",
                                            T0 + i * 200, qtype="TXT")) for i in range(60)]
    findings, _, _ = run(DnsDomainLogic(CFG, INV), obs, lambda o: f"{o['src']}|{o['registrable']}")
    assert findings and findings[0]["subtype"] == "dns_tunnel_like"
    assert findings[0]["entity_key"] == "10.10.1.50|exfil-example.org"
    alerts_for(findings)


def test_dga_burst_rules_only_without_model(rules_only_scorer):
    rng = random.Random(4)
    obs = [rules_only_scorer.observe(dns_ev("10.10.1.40", "".join(rng.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(16)) + ".com",
                                            T0 + i * 300, rcode="NXDOMAIN")) for i in range(20)]
    assert all(o["reason"] == "model_unavailable" for o in obs)
    findings, _, _ = run(DgaBurstLogic(CFG, INV), obs, lambda o: o["src"])
    assert findings[0]["subtype"] == "dga_nxdomain_burst"
    assert findings[0]["method"] == "rule" and findings[0]["model_version"] is None
    alerts = alerts_for(findings)
    assert alerts[0]["detection_method"] == "rule"


def test_allowlisted_and_internal_names_are_not_scored(rules_only_scorer):
    assert rules_only_scorer.observe(dns_ev("10.10.1.40", "hmi-01.plant.local", T0))["reason"] == "allowlisted"
    assert rules_only_scorer.observe(dns_ev("10.10.1.40", "wpad", T0))["reason"] == "not_registrable"


# ------------------------------------------------------------------ encrypted metadata

def tls_ev(t_ms, version="TLSv10", sni=None, dport=8443, dst="198.51.100.20"):
    uid = f"T{next(_uid)}"
    a = {} if sni else {"server_name": "MISSING"}
    return {"event_id": ids.derived_id("event", uid), "sensor_id": "ot-sensor-01", "boot": BOOT, "run": "r1", "offset_us": 0,
            "log_type": "ssl", "event_time_us": t_ms * 1000, "obs_ms": t_ms, "received_us": t_ms * 1000, "coverage": "both_directions",
            "p": {"uid": uid, "src_ip": "10.10.1.50", "src_port": 50000, "dst_ip": dst, "dst_port": dport, "version": version,
                  "server_name": sni, "validation_status": None}, "a": a}


def test_suspicious_tls_metadata_and_benign_tls():
    bad = [tls_ev(T0 + i * 10_000) for i in range(5)]
    good = [tls_ev(T0 + i * 10_000, version="TLSv13", sni="vendor-updates.example.com", dport=443) for i in range(5)]
    f_bad, _, _ = run(EncryptedLogic(CFG, INV), bad, lambda e: "k")
    f_good, _, _ = run(EncryptedLogic(CFG, INV), good, lambda e: "k")
    assert f_bad and f_bad[0]["subtype"] == "suspicious_tls_metadata"
    assert "certificate_not_validated" in f_bad[0]["unavailable"]
    assert f_good == []
    alerts_for(f_bad)


# ------------------------------------------------------------------ exfiltration

def test_sustained_upload_and_known_bulk_excluded():
    uid = "Cupload"
    evs = [conn("10.10.1.30", "203.0.113.77", 443, T0 + k * 5000, log_type="flow_update", seq=k, ob=k * 8_000_000, rb=k * 20_000,
                dur=k * 5, uid=uid) for k in range(1, 9)]
    backup = [conn("10.10.3.10", "198.51.100.200", 443, T0 + k * 5000, log_type="flow_update", seq=k, ob=k * 8_000_000,
                   rb=1000, dur=k * 5, uid="Cvendor") for k in range(1, 9)]
    ds, _ = deltas(evs + backup)
    logic = ExfilLogic(CFG, INV)
    eligible = [d for d in ds if logic.eligible(d)]
    assert {d["src"] for d in eligible} == {"10.10.1.30"}
    findings, _, _ = run(logic, eligible, lambda d: d["src"])
    assert findings and findings[0]["subtype"] == "sustained_upload"
    assert findings[0]["observed"]["out_in_ratio"] is not None
    alerts_for(findings)


# ------------------------------------------------------------------ incidents

def test_incident_cooldown_escalation_and_deterministic_ids():
    evs = [conn("10.10.1.99", f"10.10.2.{i}", 502, T0 + i * 100, state="S0", ob=0, rb=0, dur=None) for i in range(1, 120)]
    ds, _ = deltas(evs)
    findings, _, _ = run(ScanLogic(CFG, INV), ds, lambda d: d["src"])
    a1 = alerts_for(findings)
    a2 = alerts_for(findings)
    assert [a["update_id"] for a in a1] == [a["update_id"] for a in a2]
    statuses = [a["status"] for a in a1]
    assert statuses[0] == "new" and "escalated" in statuses and statuses[-1] == "resolved"
    assert len({a["incident_id"] for a in a1}) == 1
    assert len(a1) < len(findings) + 2
