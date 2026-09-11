"""Beaconing detector. Key: src|dst|dst_port|proto.

Keeps the last N connection start times (bounded) and flags persistent periodicity using robust statistics:
median inter-arrival time (IAT) and 1.4826*MAD/median dispersion. Evidence needs several intervals, so
detection time depends on the beacon period. Pairs listed as known periodic in the asset inventory (OT
polling, NTP) are suppressed; internal destinations get lower severity than external ones.
"""
from __future__ import annotations

import bisect
from statistics import median

from sih_detect.alerts import SEVERITY_RANK, feature_record, finding, rate_limited
from sih_detect.common import append_ids, bucket_up, ev_min, robust_cv

VERSION = "beacon-1.0.0"
FSV = "beacon_features-1.0.0"


class BeaconLogic:
    value_states = ("b",)
    map_states = ()

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory

    def open(self):
        pass

    def on_event(self, ctx, key, d):
        if not d["new_flow"]:
            return []
        cfg = self.cfg
        bv = ctx.value("b")
        b = bv.value() or {"t": [], "s": [], "ids": [], "first": ev_min(d), "rank": -1, "emitted_n": 0}
        t = d["start_ms"]
        if t in b["t"]:
            return []
        i = bisect.bisect(b["t"], t)
        b["t"].insert(i, t)
        b["s"].insert(i, d["total_orig_bytes"] if d["terminal"] else None)
        if len(b["t"]) > cfg.beacon_max_events:
            del b["t"][0]
            del b["s"][0]
        b["ids"] = append_ids(b["ids"], d["event_id"])
        b["last"] = ev_min(d)
        out = []
        n = len(b["t"])
        m_iat = None
        if n >= cfg.beacon_min_events:
            iats = [b2 - a for a, b2 in zip(b["t"], b["t"][1:])]
            m_iat = median(iats)
            cv = robust_cv(iats) if m_iat >= cfg.beacon_min_interval_ms else None
            span = b["t"][-1] - b["t"][0]
            sizes = [x for x in b["s"] if x is not None]
            size_cv = robust_cv(sizes) if len(sizes) >= 4 else None
            if cv is not None and cv <= cfg.beacon_max_cv and span >= 3 * m_iat:
                external = not self.inv.is_local(d["dst"])
                known = self.inv.known_periodic(d["src"], d["dst"], d["dport"], d["proto"])
                values = {"connections": n, "median_iat_s": m_iat / 1000, "iat_robust_cv": cv, "span_s": span / 1000,
                          "size_robust_cv": size_cv, "dst_external": 1 if external else 0, "known_periodic": 1 if known else 0}
                if known:
                    ctx.metric("beacon_suppressed_known_periodic")
                else:
                    sev = "medium" if external else "low"
                    if external and cv <= 0.05 and n >= 16:
                        sev = "high"
                    rank = SEVERITY_RANK[sev]
                    if rank > b["rank"] or n >= 2 * b["emitted_n"]:
                        b["rank"] = max(rank, b["rank"])
                        b["emitted_n"] = n
                        expl = (f"{d['src']} opened {n} connections to {d['dst']}:{d['dport']}/{d['proto']} about every "
                                f"{m_iat / 1000:.1f}s over {span / 1000:.0f}s (robust dispersion {cv:.3f}, threshold "
                                f"{cfg.beacon_max_cv}). Destination is {'outside' if external else 'inside'} the local networks "
                                "and not a known periodic pair in the asset inventory.")
                        out.append(("out", finding(
                            detector="beacon", threat_class="beaconing", subtype="periodic_beacon",
                            entity_type="service_pair", entity_key=key, severity=sev,
                            score=0.6 * max(0.0, 1 - cv / cfg.beacon_max_cv) + 0.4 * min(1.0, n / 32), method="statistical",
                            detector_version=VERSION, feature_schema_version=FSV, first=b["first"], last=b["last"],
                            window_start_ms=b["t"][0], window_end_ms=d["obs_ms"], observed=values,
                            thresholds={"max_robust_cv": cfg.beacon_max_cv, "min_connections": cfg.beacon_min_events,
                                        "min_interval_s": cfg.beacon_min_interval_ms / 1000},
                            unavailable=[] if size_cv is not None else ["size_robust_cv"], coverage=d["coverage"],
                            src_ip=d["src"], dst_ip=d["dst"], dst_port=d["dport"], protocol=d["proto"],
                            flow_id=d["flow_id"], raw_event_ids=b["ids"], evidence_count=n,
                            top_features=[("iat_robust_cv", cv, None, "ratio"), ("median_iat_s", m_iat / 1000, None, "s"),
                                          ("connections", n, None, "count"), ("size_robust_cv", size_cv, None, "ratio")],
                            explanation=expl)))
                if rate_limited(b, d["obs_ms"], cfg.feature_min_interval_ms):
                    out.append(("feature", feature_record(
                        "beacon", FSV, "service_pair", key, d["sensor_id"], b["t"][0], d["obs_ms"], values,
                        {"size_robust_cv": "UNKNOWN"})))
        bv.update(b)
        horizon = max(4 * (m_iat or 0), 600_000)
        ctx.timer(bucket_up(b["t"][-1] + horizon, 60_000))
        return out

    def on_timer(self, ctx, key, ts):
        bv = ctx.value("b")
        b = bv.value()
        if b is None:
            return []
        iats = [y - x for x, y in zip(b["t"], b["t"][1:])]
        horizon = max(4 * (median(iats) if iats else 0), 600_000)
        if b["t"][-1] + horizon <= ts:
            bv.clear()
            ctx.metric("beacon_state_expired")
        return []
