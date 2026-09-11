"""Synthetic Zeek-format JSON logs (capture_mode=synthetic_log). Never labelled as Zeek-processed captures.

Batch: write a complete run directory for the sender's replay mode (with `.done` and manifest.json).
    python -m sih_datagen.synthetic batch --out /data/synthetic-runs --rate 500 --duration 600 [--attacks]
Live: append records with current timestamps to rotating files for the sender's tail mode.
    python -m sih_datagen.synthetic live --out /data/synthetic-live --rate 200 [--rotate-s 60] [--keep 10]

Rates are offered records per second (open loop): records are laid out on a fixed schedule regardless of
downstream progress.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import string
import time
from decimal import Decimal

HOSTS = [f"10.10.{a}.{b}" for a in (1, 3, 4, 5) for b in range(10, 60)]
PLCS = [f"10.10.2.{i}" for i in range(5, 40)]
RESOLVER = "10.10.0.53"
UID_ALPHABET = string.ascii_letters + string.digits


def _uid(rng: random.Random) -> str:
    return "C" + "".join(rng.choice(UID_ALPHABET) for _ in range(17))


def _ts(us: int) -> Decimal:
    return Decimal(us) / Decimal(1_000_000)


def conn_record(rng, t_us, src, dst, dport, proto="tcp", state="SF", ob=None, rb=None, dur=None, service=None, sport=None):
    r = {"ts": _ts(t_us), "uid": _uid(rng), "id.orig_h": src, "id.orig_p": sport or rng.randint(1024, 65535),
         "id.resp_h": dst, "id.resp_p": dport, "proto": proto, "conn_state": state, "local_orig": True,
         "local_resp": dst.startswith("10."), "missed_bytes": 0,
         "history": {"SF": "ShADadFf", "S0": "S", "REJ": "Sr"}.get(state, "ShAD"),
         "orig_pkts": 1 if state in ("S0", "REJ") else rng.randint(4, 12), "resp_pkts": 0 if state == "S0" else rng.randint(1, 10)}
    if service:
        r["service"] = service
    if dur is not None:
        r["duration"] = round(Decimal(dur), 6)
    if ob is not None:
        r["orig_bytes"], r["orig_ip_bytes"] = ob, ob + 40 * r["orig_pkts"]
    if rb is not None:
        r["resp_bytes"], r["resp_ip_bytes"] = rb, rb + 40 * r["resp_pkts"]
    return r


def dns_record(rng, t_us, src, query, rcode="NOERROR", qtype="A", answers=None):
    r = {"ts": _ts(t_us), "uid": _uid(rng), "id.orig_h": src, "id.orig_p": rng.randint(20000, 60000), "id.resp_h": RESOLVER,
         "id.resp_p": 53, "proto": "udp", "trans_id": rng.randrange(65536), "rtt": Decimal("0.003"), "query": query,
         "qclass": 1, "qclass_name": "C_INTERNET", "qtype": {"A": 1, "TXT": 16}[qtype], "qtype_name": qtype,
         "rcode": {"NOERROR": 0, "NXDOMAIN": 3}[rcode], "rcode_name": rcode, "AA": False, "TC": False, "RD": True,
         "RA": True, "Z": 0, "rejected": False}
    if answers:
        r["answers"] = answers
    return r


class Stream:
    """Produces (log_type, record) tuples on an open-loop schedule."""

    def __init__(self, seed: int, rate: float, attacks: bool):
        self.rng = random.Random(seed)
        self.rate = rate
        self.attacks = attacks
        self.episodes: list[dict] = []

    def benign(self, t_us: int):
        rng = self.rng
        r = rng.random()
        if r < 0.7:
            return "conn", conn_record(rng, t_us, rng.choice(HOSTS), rng.choice(PLCS), 502, dur=rng.uniform(0.005, 0.05),
                                       ob=12, rb=rng.randint(11, 60), service="modbus")
        if r < 0.9:
            return "dns", dns_record(rng, t_us, rng.choice(HOSTS), rng.choice(["historian-01.plant.local", "vendor-updates.example.com",
                                                                                  "docs.powergridsystems.com"]), answers=["10.10.3.10"])
        return "conn", conn_record(rng, t_us, rng.choice(HOSTS), "10.10.3.10", 443, dur=rng.uniform(0.1, 2), ob=rng.randint(500, 5000),
                                   rb=rng.randint(1000, 50000), service="ssl")

    def attack(self, t_us: int, start_us: int):
        """Attack records injected on a fixed timeline relative to the stream start."""
        rng = self.rng
        rel = (t_us - start_us) / 1e6
        cycle = rel % 300
        if 30 <= cycle < 40:  # scan burst
            return "conn", conn_record(rng, t_us, "10.10.1.99", f"10.10.{rng.randint(2, 9)}.{rng.randint(1, 254)}", 502, state="S0")
        if 90 <= cycle < 110:  # DGA NXDOMAIN burst
            label = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(12, 18)))
            return "dns", dns_record(rng, t_us, "10.10.1.40", f"{label}.com", rcode="NXDOMAIN")
        if 150 <= cycle < 170:  # DNS tunnel
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(40))
            return "dns", dns_record(rng, t_us, "10.10.1.50", f"{label}.t.exfil-example.org", qtype="TXT")
        return None

    def records(self, start_us: int, duration_s: float):
        n = int(self.rate * duration_s)
        step = 1_000_000 / self.rate
        for i in range(n):
            t = start_us + int(i * step)
            rec = self.attack(t, start_us) if self.attacks and self.rng.random() < 0.2 else None
            yield rec or self.benign(t)


def _line(rec: dict) -> str:
    return json.dumps(rec, default=lambda o: float(o) if isinstance(o, Decimal) else str(o), separators=(",", ":"))


def batch(out: pathlib.Path, rate: float, duration: float, attacks: bool, seed: int) -> pathlib.Path:
    run_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-synthetic-{int(rate)}eps"
    tmp = out / f".tmp-{run_id}"
    tmp.mkdir(parents=True, exist_ok=True)
    files = {t: open(tmp / f"{t}.log", "w", encoding="utf-8") for t in ("conn", "dns")}
    start = 1_788_256_800_000_000
    stream = Stream(seed, rate, attacks)
    counts = {"conn": 0, "dns": 0}
    for log_type, rec in stream.records(start, duration):
        files[log_type].write(_line(rec) + "\n")
        counts[log_type] += 1
    for f in files.values():
        f.close()
    manifest = {"run_id": run_id, "generator": "sih_datagen.synthetic-1.0.0", "capture_mode": "synthetic_log", "seed": seed,
                "offered_rate_eps": rate, "duration_s": duration, "records": counts, "attacks": attacks,
                "attack_timeline_s": {"scan": [30, 40], "dga_nxdomain_burst": [90, 110], "dns_tunnel_like": [150, 170],
                                      "period_s": 300} if attacks else None,
                "note": "Synthetic Zeek-format records; not produced by Zeek from packets."}
    (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    final = out / run_id
    os.replace(tmp, final)
    (final / ".done").touch()
    return final


def live(out: pathlib.Path, rate: float, rotate_s: int, keep: int, attacks: bool, seed: int) -> None:
    out.mkdir(parents=True, exist_ok=True)
    stream = Stream(seed, rate, attacks)
    handles = {t: open(out / f"{t}.log", "a", encoding="utf-8") for t in ("conn", "dns")}
    opened = time.time()
    start = time.time_ns() // 1000
    i = 0
    while True:
        target = start + int(i * 1_000_000 / rate)
        now = time.time_ns() // 1000
        if target > now:
            time.sleep((target - now) / 1e6)
        rec = stream.attack(target, start) if attacks and stream.rng.random() < 0.2 else None
        log_type, record = rec or stream.benign(target)
        handles[log_type].write(_line(record) + "\n")
        if i % 50 == 0:
            for h in handles.values():
                h.flush()
        i += 1
        if time.time() - opened >= rotate_s:
            stamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.gmtime())
            for t, h in handles.items():
                h.close()
                os.rename(out / f"{t}.log", out / f"{t}.{stamp}.log")
                handles[t] = open(out / f"{t}.log", "a", encoding="utf-8")
                rotated = sorted(out.glob(f"{t}.*-*.log"))
                for old in rotated[:-keep]:
                    old.unlink()  # bounded retention: the sender must keep up within `keep` rotations
            opened = time.time()


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("batch")
    b.add_argument("--out", default="/data/synthetic-runs")
    b.add_argument("--rate", type=float, default=200)
    b.add_argument("--duration", type=float, default=300)
    b.add_argument("--attacks", action="store_true")
    b.add_argument("--seed", type=int, default=11)
    lv = sub.add_parser("live")
    lv.add_argument("--out", default="/data/synthetic-live")
    lv.add_argument("--rate", type=float, default=100)
    lv.add_argument("--rotate-s", type=int, default=60)
    lv.add_argument("--keep", type=int, default=10)
    lv.add_argument("--attacks", action="store_true")
    lv.add_argument("--seed", type=int, default=12)
    a = ap.parse_args(argv)
    if a.cmd == "batch":
        print(batch(pathlib.Path(a.out), a.rate, a.duration, a.attacks, a.seed))
    else:
        live(pathlib.Path(a.out), a.rate, a.rotate_s, a.keep, a.attacks, a.seed)


if __name__ == "__main__":
    main()
