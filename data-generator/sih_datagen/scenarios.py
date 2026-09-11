"""PCAP scenarios with ground-truth manifests.

Every address belongs to the simulated plant in data/fixtures/asset-inventory.json or to documentation /
benchmarking ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15). Labels describe what
was generated; manifests state what a passive detector can observe, never that spoofing or malware was
proven.
"""
from __future__ import annotations

import random
import string

from sih_datagen.packets import (Capture, TcpFlow, a_record, dns_exchange, syn_probe, tls_session, txt_record)

T0_US = 1_788_256_800_000_000  # 2026-09-01T10:00:00Z; replay offsets map it to wall clock
S = 1_000_000

HMI, ENG, OPS1, OPS2, OPS3 = "10.10.1.10", "10.10.1.20", "10.10.1.30", "10.10.1.40", "10.10.1.50"
PLCS = ["10.10.2.5", "10.10.2.6", "10.10.2.7"]
RTU, HIST, DNS, NTP, BACKUP, WEB = "10.10.2.8", "10.10.3.10", "10.10.0.53", "10.10.0.123", "10.20.0.80", "10.20.0.80"
BACKUP = "10.20.0.50"
SCANNER_ROGUE = "10.10.1.99"
BENIGN_NAMES = ["hmi-01.plant.local", "historian-01.plant.local", "vendor-updates.example.com", "time.plant.local",
                "docs.powergridsystems.com", "mail.steelworksgroup.co.in", "portal.waterboard.gov.in"]


def _episode(label, threat_class, subtypes, entity_type, entity_key, start_us, end_us, note, **extra):
    return {"label": label, "threat_class": threat_class, "expected_subtypes": subtypes, "entity_type": entity_type,
            "entity_key": entity_key, "start_offset_s": (start_us - T0_US) / S, "end_offset_s": (end_us - T0_US) / S,
            "note": note, **extra}


# ------------------------------------------------------------------ benign background

def benign(cap: Capture, rng: random.Random, start: int, dur_s: int) -> list[dict]:
    end = start + dur_s * S
    # Modbus/TCP polling: one persistent connection per PLC, a request every second.
    for i, plc in enumerate(PLCS):
        f = TcpFlow(cap, HMI, 49152 + i, plc, 502, rng)
        t = f.open(start + i * 37_000)
        tid = 0
        while t < end - 2 * S:
            tid = (tid + 1) & 0xFFFF
            t = f.send(t, True, tid.to_bytes(2, "big") + b"\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a")
            f.send(t + 3000, False, tid.to_bytes(2, "big") + b"\x00\x00\x00\x17\x01\x03\x14" + bytes(20))
            t += S - 1000
        f.close(end - S)
    # Historian DNP3 polls of the RTU every 10 s (short connections; a known periodic pair).
    t = start + 2 * S
    while t < end - S:
        f = TcpFlow(cap, HIST, rng.randint(40000, 60000), RTU, 20000, rng)
        f.close(f.send(f.send(f.open(t), True, bytes(18)), False, bytes(64)))
        t += 10 * S
    # NTP every 16 s from the engineering workstation (known periodic).
    t = start + 1 * S
    while t < end:
        sport = 123
        cap.udp(t, ENG, sport, NTP, 123, b"\x23" + bytes(47))
        cap.udp(t + 800, NTP, 123, ENG, sport, b"\x24" + bytes(47))
        t += 16 * S
    # Irregular DNS lookups and TLS 1.3 update checks (not periodic).
    t = start + 500_000
    while t < end:
        dns_exchange(cap, t, rng.choice([OPS1, OPS2, OPS3, ENG]), DNS, rng.choice(BENIGN_NAMES), rng,
                     answers=[a_record("10.10.1.10")])
        t += rng.randint(2, 9) * S + rng.randint(0, 999_999)
    t = start + 5 * S
    while t < end - 3 * S:
        tls_session(cap, t, OPS1, rng.randint(40000, 60000), "198.51.100.10", 443, rng, sni="vendor-updates.example.com", tls13=True)
        t += rng.randint(20, 120) * S
    # Internal historian backup (known bulk transfer; internal destination).
    f = TcpFlow(cap, HIST, 45000, BACKUP, 873, rng)
    f.close(f.send(f.open(start + 30 * S), True, bytes(2_000_000), gap_us=20))
    return [{"label": "benign_ot_background",
             "description": "Modbus polling (1 s), DNP3 historian polls (10 s), NTP (16 s), irregular DNS and TLS 1.3 update checks, internal backup",
             "expected": "no alerts; known periodic pairs suppressed by the asset inventory"}]


# ------------------------------------------------------------------ attacks

def spoofed_syn_flood(cap, rng, start, n=3000, dur_s=3):
    for i in range(n):
        src = f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        syn_probe(cap, start + i * (dur_s * S // n), src, rng.randint(1024, 65535), WEB, 80, rng, None)
    return _episode("spoofed_source_like_syn_flood", "ddos", ["spoofed_source_like_flood", "syn_flood"], "dst_host", WEB,
                    start, start + dur_s * S, "Single-SYN connection attempts from randomized 198.18.0.0/15 sources; "
                    "observable as many sources with about one flow each, not as proven spoofing.")


def syn_flood_few_sources(cap, rng, start, n=600, dur_s=3):
    srcs = ["203.0.113.21", "203.0.113.22", "203.0.113.23", "203.0.113.24"]
    for i in range(n):
        syn_probe(cap, start + i * (dur_s * S // n), srcs[i % 4], 10000 + i, WEB, 443, rng, None)
    return _episode("syn_flood", "ddos", ["syn_flood"], "dst_host", WEB, start, start + dur_s * S,
                    "SYNs without replies from four sources.")


def udp_amplification(cap, rng, start, reflectors=80, pkts=25, dur_s=3):
    for r in range(reflectors):
        src = f"192.0.2.{r + 10}"
        sport = rng.choice([53, 123, 1900, 11211])
        dport = rng.randint(30000, 60000)
        for k in range(pkts):
            cap.udp(start + r * 3000 + k * (dur_s * S // pkts), src, sport, WEB, dport, bytes(rng.randrange(256) for _ in range(1400)))
    return _episode("udp_amplification_like", "ddos", ["udp_amplification_like"], "dst_host", WEB, start, start + dur_s * S,
                    "Large unsolicited UDP datagrams from amplification-prone source ports; request traffic is not visible.")


def beaconing(cap, rng, start, count=18, period_s=30, jitter_ms=1000):
    for i in range(count):
        t = start + i * period_s * S + rng.randint(-jitter_ms, jitter_ms) * 1000
        f = TcpFlow(cap, OPS2, rng.randint(40000, 60000), "203.0.113.10", 443, rng)
        f.close(f.send(f.send(f.open(t), True, bytes(rng.randrange(256) for _ in range(310))), False, bytes(220)))
    return _episode("periodic_beacon", "beaconing", ["periodic_beacon"], "service_pair", f"{OPS2}|203.0.113.10|443|tcp",
                    start, start + count * period_s * S, f"Connections every {period_s}s with +/-{jitter_ms}ms jitter to an external host.")


def dga(cap, rng, start, n=40, dur_s=20):
    for i in range(n):
        label = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(12, 18)))
        dns_exchange(cap, start + i * (dur_s * S // n), OPS2, DNS, f"{label}.{rng.choice(['com', 'net', 'info'])}", rng, rcode=3)
    return _episode("dga_nxdomain_burst", "dga", ["dga_nxdomain_burst", "dga_domain"], "src_host", OPS2, start, start + dur_s * S,
                    "Uniform-random labels (a training-family style, unseen seeds) answered NXDOMAIN.")


def dns_tunnel(cap, rng, start, n=120, dur_s=60):
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(n):
        label = "".join(rng.choice(alphabet) for _ in range(40))
        dns_exchange(cap, start + i * (dur_s * S // n), OPS3, DNS, f"{label}.t.exfil-example.org", rng, qtype=16,
                     answers=[txt_record(b"ok")])
    return _episode("dns_tunnel_like", "dns_tunnel", ["dns_tunnel_like"], "src_domain", f"{OPS3}|exfil-example.org", start,
                    start + dur_s * S, "Base32-like 40-character labels in TXT queries under one registrable domain.")


def encrypted_metadata(cap, rng, start, n=8, period_s=20):
    for i in range(n):
        tls_session(cap, start + i * period_s * S + rng.randint(0, 3 * S), OPS3, rng.randint(40000, 60000), "198.51.100.20", 8443,
                    rng, version=0x0301, sni=None)
    return _episode("suspicious_tls_metadata", "encrypted_malware_like", ["suspicious_tls_metadata"], "service_pair",
                    f"{OPS3}|198.51.100.20|8443", start, start + n * period_s * S,
                    "TLS 1.0 handshakes without SNI to an external host; metadata only, no decryption.")


def scanning(cap, rng, start):
    t = start
    for i in range(1, 61):  # horizontal: port 502 across a /24
        ans = "synack" if f"10.10.2.{i}" in PLCS else ("rst" if i % 3 else None)
        syn_probe(cap, t, SCANNER_ROGUE, 40000 + i, f"10.10.2.{i}", 502, rng, ans)
        t += 150_000
    for port in range(1, 201):  # vertical: one PLC
        syn_probe(cap, t, SCANNER_ROGUE, 50000 + port, PLCS[0], port, rng, "synack" if port == 502 else "rst")
        t += 40_000
    return _episode("scan", "scan", ["horizontal_scan", "vertical_scan"], "src_host", SCANNER_ROGUE, start, t,
                    "60 hosts on 502/tcp then 200 ports on one PLC from an unlisted host.")


def exfiltration(cap, rng, start, total_bytes=18_000_000, dur_s=40):
    f = TcpFlow(cap, OPS1, 51000, "203.0.113.77", 443, rng)
    t = f.open(start)
    chunk = 450_000
    gap = max(20, (dur_s * S) // (total_bytes // 1448))
    payload = bytes(rng.randrange(256) for _ in range(chunk))
    sent = 0
    while sent < total_bytes:
        t = f.send(t, True, payload, gap_us=gap)
        sent += chunk
    f.close(t)
    return _episode("sustained_upload", "exfiltration", ["sustained_upload"], "src_host", OPS1, start, t,
                    f"{total_bytes / 1e6:.0f} MB upload over about {dur_s}s to an external host not in the inventory.")


def malformed(cap, rng, start):
    for i in range(20):
        cap.raw_ip(start + i * 10_000, b"\x02\x00\x0a\x0a\x01\x0a" * 2 + b"\x08\x00" + b"\x45\x00\x00\x10" + bytes(8))
    return {"label": "malformed_frames", "note": "Truncated IPv4 headers; Zeek reports weird records; no alert expected."}


# ------------------------------------------------------------------ scenario table

def _build(name: str, dur_s: int, attacks) -> tuple[Capture, dict]:
    rng = random.Random(f"sih-{name}")
    cap = Capture()
    bg = benign(cap, rng, T0_US, dur_s)
    episodes = [a(cap, rng) for a in attacks]
    return cap, {"scenario": name, "generator": "sih_datagen.scenarios-1.0.0", "seed": f"sih-{name}",
                 "capture_mode": "pcap_replay", "observation_coverage": "both_directions",
                 "capture_start_us": T0_US, "duration_s": dur_s, "background": bg,
                 "episodes": [e for e in episodes if e.get("threat_class")],
                 "other": [e for e in episodes if not e.get("threat_class")],
                 "absent_expected": [{"threat_class": c, "entity_key": k} for c, k in
                                     (("scan", HMI), ("beaconing", f"{HIST}|{RTU}|20000|tcp"), ("beaconing", f"{ENG}|{NTP}|123|udp"),
                                      ("exfiltration", HIST))]}


def _at(offset_s):
    return T0_US + offset_s * S


SCENARIOS = {
    "benign": lambda: _build("benign", 120, []),
    "syn_flood": lambda: _build("syn_flood", 60, [lambda c, r: spoofed_syn_flood(c, r, _at(20))]),
    "syn_flood_few": lambda: _build("syn_flood_few", 60, [lambda c, r: syn_flood_few_sources(c, r, _at(20))]),
    "udp_amplification": lambda: _build("udp_amplification", 60, [lambda c, r: udp_amplification(c, r, _at(20))]),
    "beaconing": lambda: _build("beaconing", 560, [lambda c, r: beaconing(c, r, _at(5))]),
    "dga": lambda: _build("dga", 90, [lambda c, r: dga(c, r, _at(30))]),
    "dns_tunnel": lambda: _build("dns_tunnel", 100, [lambda c, r: dns_tunnel(c, r, _at(20))]),
    "encrypted": lambda: _build("encrypted", 200, [lambda c, r: encrypted_metadata(c, r, _at(10))]),
    "scan": lambda: _build("scan", 90, [lambda c, r: scanning(c, r, _at(20))]),
    "exfiltration": lambda: _build("exfiltration", 120, [lambda c, r: exfiltration(c, r, _at(30))]),
    "malformed": lambda: _build("malformed", 30, [lambda c, r: malformed(c, r, _at(5))]),
    "mixed": lambda: _build("mixed", 600, [
        lambda c, r: beaconing(c, r, _at(5)),
        lambda c, r: scanning(c, r, _at(60)),
        lambda c, r: dga(c, r, _at(120)),
        lambda c, r: dns_tunnel(c, r, _at(180)),
        lambda c, r: encrypted_metadata(c, r, _at(60)),
        lambda c, r: spoofed_syn_flood(c, r, _at(260)),
        lambda c, r: udp_amplification(c, r, _at(320)),
        lambda c, r: exfiltration(c, r, _at(400)),
    ]),
}
