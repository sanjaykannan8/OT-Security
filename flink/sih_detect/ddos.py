"""Flood detector. Key: destination host.

One-second buckets (ten retained) of new flows, SYN-only attempts, bytes, packets and amplification-port
traffic, plus source cardinality sketches. Each record is evaluated against the current bucket and a
five-second window, so an alert fires inside the first anomalous second. The baseline (EWMA over closed
active seconds) only learns from non-anomalous buckets. Subtype names describe what is observable:
"spoofed_source_like" means many sources with about one flow each, not proof of spoofing.
"""
from __future__ import annotations

from sih_detect.alerts import SEVERITY_RANK, feature_record, finding, rate_limited
from sih_detect.common import Cardinality, Ewma, append_ids, bucket_up, ev_min

VERSION = "ddos-1.0.0"
FSV = "ddos_features-1.0.0"
AMP_PORTS = frozenset({19, 53, 111, 123, 137, 161, 389, 1900, 3702, 5353, 11211})
PRIORITY = {"udp_amplification_like": 3, "spoofed_source_like_flood": 2, "syn_flood": 1, "volumetric_flood": 0}
KEEP_BUCKETS = 10


def _new_bucket() -> dict:
    return {"flows": 0, "syn": 0, "bytes": 0, "pkts": 0, "bytes_unknown": False, "pkts_unknown": False,
            "amp_flows": 0, "amp_bytes": 0, "srcs": Cardinality.new(), "amp_srcs": Cardinality.new(),
            "anomalous": False}


class DdosLogic:
    value_states = ("s",)
    map_states = ()

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory

    def open(self):
        pass

    def on_event(self, ctx, dst, d):
        cfg = self.cfg
        sv = ctx.value("s")
        s = sv.value() or {"b": {}, "flows": Ewma.new(), "bytes": Ewma.new(), "episode": None, "ids": [],
                           "first": ev_min(d)}
        sec = d["obs_ms"] // 1000
        self._close_old(s, sec)
        b = s["b"].setdefault(sec, _new_bucket())
        amp = d["proto"] == "udp" and d.get("sport") in AMP_PORTS
        if d["new_flow"]:
            b["flows"] += 1
            Cardinality.add(b["srcs"], d["src"])
            if d["proto"] == "tcp" and d["terminal"] and d.get("conn_state") == "S0":
                b["syn"] += 1
            if amp:
                b["amp_flows"] += 1
                Cardinality.add(b["amp_srcs"], d["src"])
        dd = d["d"]
        for fld, unknown in (("bytes", "bytes_unknown"), ("pkts", "pkts_unknown")):
            parts = (dd[f"orig_{fld}"], dd[f"resp_{fld}"])
            if any(v is None for v in parts):
                b[unknown] = True
            b[fld] += sum(v for v in parts if v is not None)
        if amp and dd["orig_bytes"] is not None:
            b["amp_bytes"] += dd["orig_bytes"]
        s["ids"] = append_ids(s["ids"], d["event_id"])
        s["last"] = ev_min(d)

        window = [s["b"][k] for k in s["b"] if sec - 4 <= k <= sec]
        w_flows = sum(x["flows"] for x in window)
        srcs = Cardinality.merge([x["srcs"] for x in window])
        w_srcs = Cardinality.count(srcs)
        w_amp_srcs = Cardinality.count(Cardinality.merge([x["amp_srcs"] for x in window]))
        warm = s["flows"]["n"] >= cfg.ddos_warmup_buckets
        thr_flows = max(cfg.ddos_min_flows_per_s, s["flows"]["mean"] + cfg.ddos_baseline_k * Ewma.std(s["flows"])) if warm else cfg.ddos_min_flows_per_s
        thr_bytes = max(cfg.ddos_min_bytes_per_s, s["bytes"]["mean"] + cfg.ddos_baseline_k * Ewma.std(s["bytes"])) if warm else cfg.ddos_min_bytes_per_s

        subtype = None
        if b["amp_bytes"] >= cfg.ddos_amp_min_bytes_per_s and w_amp_srcs >= cfg.ddos_amp_min_reflectors_5s:
            subtype = "udp_amplification_like"
        elif w_srcs >= cfg.ddos_spoof_min_sources_5s and w_flows / max(1, w_srcs) <= 1.5 and b["flows"] >= thr_flows / 2:
            subtype = "spoofed_source_like_flood"
        elif b["syn"] >= cfg.ddos_syn_min_per_s and b["syn"] >= 0.8 * b["flows"]:
            subtype = "syn_flood"
        elif b["flows"] >= thr_flows or b["bytes"] >= thr_bytes:
            subtype = "volumetric_flood"

        out = []
        if subtype:
            b["anomalous"] = True
            factor = max(b["flows"] / thr_flows, b["bytes"] / thr_bytes,
                         b["amp_bytes"] / cfg.ddos_amp_min_bytes_per_s if subtype == "udp_amplification_like" else 0)
            sev = "critical" if factor >= 10 else "high"
            ep = s["episode"]
            if ep is None or d["obs_ms"] > ep["last"] + cfg.ddos_episode_gap_ms:
                ep = {"start": d["obs_ms"], "last": d["obs_ms"], "rank": -1, "prio": -1, "emitted_flows": 0}
            ep["last"] = d["obs_ms"]
            rank, prio = SEVERITY_RANK[sev], PRIORITY[subtype]
            if rank > ep["rank"] or prio > ep["prio"] or w_flows >= 2 * max(1, ep["emitted_flows"]):
                ep["rank"], ep["prio"] = max(rank, ep["rank"]), max(prio, ep["prio"])
                ep["emitted_flows"] = w_flows
                unavailable = [n for n, u in (("bytes_per_s", b["bytes_unknown"]), ("pkts_per_s", b["pkts_unknown"])) if u]
                capped = ["distinct_sources_5s"] if Cardinality.is_estimate(srcs) else []
                expl = (f"Destination {dst} received {b['flows']} new flows and {b['bytes']} bytes in one second "
                        f"(flow threshold {thr_flows:.0f}/s) from about {w_srcs} sources in 5 s.")
                if subtype == "syn_flood":
                    expl += f" {b['syn']} were connection attempts with no observed reply."
                elif subtype == "udp_amplification_like":
                    expl += f" {b['amp_bytes']} bytes/s arrived from {w_amp_srcs} sources using amplification-prone UDP ports."
                elif subtype == "spoofed_source_like_flood":
                    expl += " Sources average at most 1.5 flows each; this pattern is consistent with, but does not prove, spoofed sources."
                if capped:
                    expl += " Source count is a sketch estimate."
                out.append(("out", finding(
                    detector="ddos", threat_class="ddos", subtype=subtype, entity_type="dst_host", entity_key=dst,
                    severity=sev, score=min(1.0, 0.5 + 0.05 * factor), method="statistical" if warm else "rule",
                    detector_version=VERSION, feature_schema_version=FSV, first=s["first"], last=s["last"],
                    window_start_ms=(sec - 4) * 1000, window_end_ms=d["obs_ms"],
                    observed={"flows_per_s": b["flows"], "syn_only_per_s": b["syn"], "bytes_per_s": None if b["bytes_unknown"] else b["bytes"],
                              "pkts_per_s": None if b["pkts_unknown"] else b["pkts"], "distinct_sources_5s": w_srcs,
                              "flows_per_source_5s": w_flows / max(1, w_srcs), "amp_bytes_per_s": b["amp_bytes"],
                              "amp_sources_5s": w_amp_srcs},
                    thresholds={"flows_per_s": thr_flows, "bytes_per_s": thr_bytes, "syn_only_per_s": cfg.ddos_syn_min_per_s,
                                "spoof_min_sources_5s": cfg.ddos_spoof_min_sources_5s,
                                "amp_bytes_per_s": cfg.ddos_amp_min_bytes_per_s},
                    baseline={"flows_mean": s["flows"]["mean"] if warm else None,
                              "flows_std": Ewma.std(s["flows"]) if warm else None,
                              "bytes_mean": s["bytes"]["mean"] if warm else None},
                    unavailable=unavailable, capped=capped, coverage=d["coverage"], dst_ip=dst, protocol=d["proto"],
                    raw_event_ids=s["ids"], evidence_count=w_flows,
                    top_features=[("flows_per_s", b["flows"], None, "1/s"), ("distinct_sources_5s", w_srcs, None, "count"),
                                  ("syn_only_per_s", b["syn"], None, "1/s"), ("amp_bytes_per_s", b["amp_bytes"], None, "B/s")],
                    explanation=expl)))
            s["episode"] = ep
        if (b["flows"] >= thr_flows / 4 or subtype) and rate_limited(s, d["obs_ms"], cfg.feature_min_interval_ms):
            out.append(("feature", feature_record(
                "ddos", FSV, "dst_host", dst, d["sensor_id"], (sec - 4) * 1000, d["obs_ms"],
                {"flows_per_s": b["flows"], "syn_only_per_s": b["syn"],
                 "bytes_per_s": None if b["bytes_unknown"] else b["bytes"],
                 "pkts_per_s": None if b["pkts_unknown"] else b["pkts"],
                 "distinct_sources_5s": w_srcs, "flows_per_source_5s": w_flows / max(1, w_srcs),
                 "amp_bytes_per_s": b["amp_bytes"], "amp_sources_5s": w_amp_srcs,
                 "baseline_flows_mean": s["flows"]["mean"] if warm else None,
                 "baseline_flows_std": Ewma.std(s["flows"]) if warm else None},
                {"bytes_per_s": "UNKNOWN", "pkts_per_s": "UNKNOWN", "baseline_flows_mean": "MISSING",
                 "baseline_flows_std": "MISSING"},
                ["distinct_sources_5s"] if Cardinality.is_estimate(srcs) else [])))
        sv.update(s)
        ctx.timer(bucket_up(d["obs_ms"] + cfg.ddos_idle_ms, 10_000))
        return out

    def _close_old(self, s: dict, sec: int) -> None:
        """Fold closed seconds into the baseline (non-anomalous only) and drop old buckets."""
        for k in sorted(s["b"]):
            if k >= sec:
                break
            bk = s["b"][k]
            if not bk.get("closed"):
                bk["closed"] = True
                if not bk["anomalous"]:
                    Ewma.update(s["flows"], bk["flows"])
                    if not bk["bytes_unknown"]:
                        Ewma.update(s["bytes"], bk["bytes"])
            if k < sec - KEEP_BUCKETS:
                del s["b"][k]

    def on_timer(self, ctx, dst, ts):
        sv = ctx.value("s")
        s = sv.value()
        if s is not None and s["last"]["obs_ms"] + self.cfg.ddos_idle_ms <= ts:
            sv.clear()
            ctx.metric("ddos_state_expired")
        return []
