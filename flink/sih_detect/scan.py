"""Scan detector. Key: source host.

Tracks distinct (destination, port/proto) pairs first contacted within a bounded horizon, with running
counts of hosts per port (horizontal) and ports per host (vertical). Evaluation is incremental per new
flow, so an alert fires as soon as a threshold is crossed; expiry runs on event-time timers. The failed
outcome ratio is only computed when both directions are observed.
"""
from __future__ import annotations

from sih_detect.alerts import SEVERITY_RANK, feature_record, finding, rate_limited
from sih_detect.common import append_ids, bucket_up, ev_min

VERSION = "scan-1.0.0"
FSV = "scan_features-1.0.0"
FAILED_STATES = frozenset({"S0", "REJ", "RSTOS0", "SH"})
EXPIRY_STEP_MS = 5000


class ScanLogic:
    value_states = ("meta",)
    map_states = ("pairs", "port_hosts", "host_ports")

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory

    def open(self):
        pass

    def on_event(self, ctx, src, d):
        if not d["new_flow"]:
            return []
        cfg = self.cfg
        pairs, ph, hp = ctx.map("pairs"), ctx.map("port_hosts"), ctx.map("host_ports")
        mv = ctx.value("meta")
        m = mv.value() or {"n": 0, "hosts": 0, "ports": 0, "capped": False, "failed": 0, "known": 0,
                           "first": ev_min(d), "levels": {}, "emitted": {}, "ids": []}
        port_key = f"{d['dport']}/{d['proto']}"
        pair = f"{d['dst']}|{port_key}"
        prev = pairs.get(pair)
        if prev is None:
            if m["n"] >= cfg.scan_pair_cap:
                m["capped"] = True
                ctx.metric("scan_pair_cap_reached")
            else:
                pairs.put(pair, d["obs_ms"])
                m["n"] += 1
                c = ph.get(port_key)
                if c is None:
                    m["ports"] += 1
                ph.put(port_key, (c or 0) + 1)
                c = hp.get(d["dst"])
                if c is None:
                    m["hosts"] += 1
                hp.put(d["dst"], (c or 0) + 1)
        else:
            pairs.put(pair, max(prev, d["obs_ms"]))
        if d["terminal"] and d["coverage"] == "both_directions" and d.get("conn_state"):
            m["known"] += 1
            if d["conn_state"] in FAILED_STATES:
                m["failed"] += 1
        m["ids"] = append_ids(m["ids"], d["event_id"])
        m["last"] = ev_min(d)
        hosts_on_port = ph.get(port_key) or 0
        ports_on_host = hp.get(d["dst"]) or 0
        failed_ratio = m["failed"] / m["known"] if m["known"] and d["coverage"] == "both_directions" else None
        out = []
        checks = (
            ("horizontal_scan", hosts_on_port, cfg.scan_host_threshold,
             dict(dst_ip=None, dst_port=d["dport"]), f"{hosts_on_port} distinct hosts on port {port_key}"),
            ("vertical_scan", ports_on_host, cfg.scan_port_threshold,
             dict(dst_ip=d["dst"], dst_port=None), f"{ports_on_host} distinct ports on host {d['dst']}"),
        )
        for subtype, count, thr, dst_fields, what in checks:
            if count < thr:
                continue
            sev = "high" if count >= 5 * thr or (failed_ratio is not None and failed_ratio >= 0.8 and count >= 2 * thr) else "medium"
            allowed = self.inv.authorized_scanner(src)
            if allowed:
                sev = "info"
            rank = SEVERITY_RANK[sev]
            if rank <= m["levels"].get(subtype, -1) and count < 2 * m["emitted"].get(subtype, 0):
                continue
            m["levels"][subtype] = rank
            m["emitted"][subtype] = count
            unavailable = [] if failed_ratio is not None else ["failed_ratio"]
            capped = ["distinct_pairs"] if m["capped"] else []
            expl = (f"Source {src} contacted {what} within {cfg.scan_horizon_ms // 1000}s "
                    f"(threshold {thr}); {m['n']} distinct host/port pairs in total.")
            if failed_ratio is not None:
                expl += f" {failed_ratio:.0%} of observed attempts received no reply or a reset."
            if allowed:
                expl += " Source is listed as an authorized scanner in the asset inventory."
            out.append(("out", finding(
                detector="scan", threat_class="scan", subtype=subtype, entity_type="src_host", entity_key=src,
                severity=sev, score=min(1.0, 0.5 + 0.5 * count / (4 * thr)), method="rule",
                detector_version=VERSION, feature_schema_version=FSV, first=m["first"], last=m["last"],
                window_start_ms=max(m["first"]["obs_ms"], d["obs_ms"] - cfg.scan_horizon_ms), window_end_ms=d["obs_ms"],
                observed={"distinct_count": count, "distinct_pairs": m["n"], "distinct_hosts": m["hosts"],
                          "distinct_ports": m["ports"], "failed_ratio": failed_ratio,
                          "authorized_scanner": allowed},
                thresholds={"distinct_threshold": thr, "horizon_s": cfg.scan_horizon_ms / 1000},
                unavailable=unavailable, capped=capped, coverage=d["coverage"], src_ip=src,
                protocol=d["proto"], raw_event_ids=m["ids"], evidence_count=m["n"],
                top_features=[(subtype.split("_")[0] + "_distinct", count, None, "count"),
                              ("failed_ratio", failed_ratio, None, "ratio")],
                explanation=expl, **dst_fields)))
        top = max(hosts_on_port / cfg.scan_host_threshold, ports_on_host / cfg.scan_port_threshold)
        if top >= 0.5 and rate_limited(m, d["obs_ms"], cfg.feature_min_interval_ms):
            out.append(("feature", feature_record(
                "scan", FSV, "src_host", src, d["sensor_id"], d["obs_ms"] - cfg.scan_horizon_ms, d["obs_ms"],
                {"distinct_pairs": m["n"], "distinct_hosts": m["hosts"], "distinct_ports": m["ports"],
                 "hosts_on_port": hosts_on_port, "ports_on_host": ports_on_host, "failed_ratio": failed_ratio},
                {"failed_ratio": "UNKNOWN"}, ["distinct_pairs"] if m["capped"] else [])))
        mv.update(m)
        ctx.timer(bucket_up(d["obs_ms"], EXPIRY_STEP_MS))
        return out

    def on_timer(self, ctx, src, ts):
        mv = ctx.value("meta")
        m = mv.value()
        if m is None:
            return []
        pairs, ph, hp = ctx.map("pairs"), ctx.map("port_hosts"), ctx.map("host_ports")
        cutoff = ts - self.cfg.scan_horizon_ms
        for pair, seen in list(pairs.items()):  # copy: never mutate Flink MapState while iterating it
            if seen >= cutoff:
                continue
            pairs.remove(pair)
            dst, port_key = pair.split("|", 1)
            m["n"] -= 1
            for mp, k, field in ((ph, port_key, "ports"), (hp, dst, "hosts")):
                c = (mp.get(k) or 1) - 1
                if c <= 0:
                    mp.remove(k)
                    m[field] -= 1
                else:
                    mp.put(k, c)
        if m["n"] <= 0:
            for s in (pairs, ph, hp):
                s.clear()
            mv.clear()
            ctx.metric("scan_state_expired")
        else:
            m["capped"] = m["capped"] and m["n"] >= self.cfg.scan_pair_cap
            mv.update(m)
            ctx.timer(ts + EXPIRY_STEP_MS)
        return []
