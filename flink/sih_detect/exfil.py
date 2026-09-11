"""Exfiltration detector. Key: local source host.

Sums outbound (originator) byte deltas from local assets to external destinations over a sliding window,
compared with a per-source baseline of previous windows. A sustained transfer requires volume, duration
and several contributing records (flow_update snapshots make long uploads visible before they end). Known
bulk transfers from the asset inventory are excluded; the inbound/outbound ratio is used only when both
directions are observed.
"""
from __future__ import annotations

from sih_detect.alerts import SEVERITY_RANK, feature_record, finding, rate_limited
from sih_detect.common import Ewma, append_ids, bucket_up, ev_min

VERSION = "exfil-1.0.0"
FSV = "exfil_features-1.0.0"
MAX_RECORDS = 2048


class ExfilLogic:
    value_states = ("x",)
    map_states = ("dsts",)

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory

    def open(self):
        pass

    def eligible(self, d: dict) -> bool:
        return (self.inv.is_local(d["src"]) and not self.inv.is_local(d["dst"])
                and not self.inv.known_bulk(d["src"], d["dst"]) and (d["d"]["orig_bytes"] or 0) > 0)

    def on_event(self, ctx, src, d):
        cfg = self.cfg
        xv, dsts = ctx.value("x"), ctx.map("dsts")
        x = xv.value() or {"recs": [], "base": Ewma.new(), "win": None, "win_bytes": 0, "win_anomalous": False,
                           "first": ev_min(d), "ids": [], "rank": -1, "emitted_bytes": 0, "ndst": 0}
        now = d["obs_ms"]
        win = now // cfg.exfil_window_ms
        if x["win"] is not None and win != x["win"]:
            if not x["win_anomalous"]:
                Ewma.update(x["base"], x["win_bytes"], alpha=0.1)
            x["win_bytes"], x["win_anomalous"] = 0, False
        x["win"] = win
        out_b = d["d"]["orig_bytes"]
        in_b = d["d"]["resp_bytes"] if d["coverage"] == "both_directions" else None
        x["recs"].append((now, out_b, in_b, d["dst"]))
        x["win_bytes"] += out_b
        cutoff = now - cfg.exfil_window_ms
        x["recs"] = [r for r in x["recs"] if r[0] >= cutoff][-MAX_RECORDS:]
        new_dst = not dsts.contains(d["dst"])
        if new_dst and x["ndst"] < cfg.exfil_dst_cap:
            dsts.put(d["dst"], now)
            x["ndst"] += 1
        x["ids"] = append_ids(x["ids"], d["event_id"])
        x["last"] = ev_min(d)
        recs = x["recs"]
        out_sum = sum(r[1] for r in recs)
        ins = [r[2] for r in recs]
        in_sum = None if any(v is None for v in ins) else sum(ins)
        span = recs[-1][0] - recs[0][0]
        warm = x["base"]["n"] >= 6
        thr = max(cfg.exfil_min_bytes, cfg.exfil_baseline_k * x["base"]["mean"]) if warm else cfg.exfil_min_bytes
        ratio = out_sum / in_sum if in_sum else None
        out = []
        if out_sum >= thr and span >= cfg.exfil_min_span_ms and len(recs) >= cfg.exfil_min_records:
            x["win_anomalous"] = True
            sev = "high" if out_sum >= 5 * thr or (new_dst and out_sum >= 2 * thr) else "medium"
            rank = SEVERITY_RANK[sev]
            if rank > x["rank"] or out_sum >= 2 * max(1, x["emitted_bytes"]):
                x["rank"] = max(rank, x["rank"])
                x["emitted_bytes"] = out_sum
                rate = out_sum / max(1.0, span / 1000)
                out.append(("out", finding(
                    detector="exfil", threat_class="exfiltration", subtype="sustained_upload", entity_type="src_host",
                    entity_key=src, severity=sev, score=min(1.0, 0.5 + 0.1 * out_sum / thr),
                    method="statistical" if warm else "rule", detector_version=VERSION, feature_schema_version=FSV,
                    first=x["first"], last=x["last"], window_start_ms=recs[0][0], window_end_ms=now,
                    observed={"outbound_bytes_window": out_sum, "outbound_rate_bps": rate * 8, "span_s": span / 1000,
                              "records": len(recs), "inbound_bytes_window": in_sum, "out_in_ratio": ratio,
                              "new_destination": new_dst, "destination": d["dst"]},
                    thresholds={"min_bytes_window": thr, "min_span_s": cfg.exfil_min_span_ms / 1000,
                                "window_s": cfg.exfil_window_ms / 1000},
                    baseline={"window_bytes_mean": x["base"]["mean"] if warm else None,
                              "window_bytes_std": Ewma.std(x["base"]) if warm else None},
                    unavailable=[k for k, v in (("inbound_bytes_window", in_sum), ("out_in_ratio", ratio)) if v is None],
                    coverage=d["coverage"], src_ip=src, dst_ip=d["dst"], dst_port=d["dport"], protocol=d["proto"],
                    flow_id=d["flow_id"], raw_event_ids=x["ids"], evidence_count=len(recs),
                    top_features=[("outbound_bytes_window", out_sum, None, "B"), ("span_s", span / 1000, None, "s"),
                                  ("out_in_ratio", ratio, None, "ratio")],
                    explanation=(f"Local host {src} sent {out_sum / 1e6:.1f} MB to external destinations over "
                                 f"{span / 1000:.0f}s (threshold {thr / 1e6:.1f} MB per {cfg.exfil_window_ms // 1000}s window"
                                 f"{', learned baseline' if warm else ', baseline still warming up'}). "
                                 f"{'First transfer to ' + d['dst'] + ' seen from this host.' if new_dst else ''}"))))
        if out_sum >= thr / 4 and rate_limited(x, now, cfg.feature_min_interval_ms):
            out.append(("feature", feature_record(
                "exfil", FSV, "src_host", src, d["sensor_id"], recs[0][0], now,
                {"outbound_bytes_window": out_sum, "inbound_bytes_window": in_sum, "out_in_ratio": ratio,
                 "span_s": span / 1000, "records": len(recs),
                 "baseline_window_bytes_mean": x["base"]["mean"] if warm else None},
                {"inbound_bytes_window": "UNKNOWN", "out_in_ratio": "UNKNOWN", "baseline_window_bytes_mean": "MISSING"})))
        xv.update(x)
        ctx.timer(bucket_up(now + 600_000, 60_000))
        return out

    def on_timer(self, ctx, src, ts):
        xv = ctx.value("x")
        x = xv.value()
        if x is not None and x["last"]["obs_ms"] + 600_000 <= ts:
            xv.clear()
            ctx.map("dsts").clear()
        return []
