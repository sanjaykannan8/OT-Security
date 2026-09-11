"""Convert cumulative flow snapshots and terminal conn summaries into per-record deltas exactly once.

Key: sensor|boot|run|uid. A flow_update adds (current - previous) per counter; the terminal conn adds only
what remains; counters never move backwards (a regression is a quality event, not negative traffic). Short
flows that only ever produce a terminal conn keep no state. Late snapshots after the terminal record, and
duplicate snapshot sequence numbers, are dropped and counted.
"""
from __future__ import annotations

COUNTERS = ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")


def _bucket_up(ts_ms: int, step: int = 10_000) -> int:
    return (ts_ms // step + 1) * step


class FlowDeltaLogic:
    value_states = ("flow",)
    map_states = ()

    def __init__(self, cfg):
        self.idle_ms = cfg.flow_idle_ms
        self.tombstone_ms = cfg.flow_tombstone_ms

    def open(self):
        pass

    def on_event(self, ctx, key, ev):
        p = ev["p"]
        st_v = ctx.value("flow")
        st = st_v.value()
        terminal = ev["log_type"] == "conn"
        if st is not None and st.get("term"):
            ctx.metric("flow_late_after_terminal")
            return []
        if not terminal and st is not None and p["snapshot_seq"] <= st["seq"]:
            ctx.metric("flow_duplicate_snapshot")
            return []
        prev = st["c"] if st else {}
        deltas = {}
        for c in COUNTERS:
            cur = p.get(c)
            if cur is None:
                deltas[c] = None  # unavailable stays unavailable
                continue
            before = prev.get(c) or 0
            if cur < before:
                ctx.metric("flow_counter_regression")
                deltas[c] = 0
            else:
                deltas[c] = cur - before
        start_ms = (ev["event_time_us"] + ev["offset_us"]) // 1000
        if not terminal and p.get("duration_s") is not None:
            start_ms -= int(p["duration_s"] * 1000)  # snapshot ts is the poll time
        out = {
            "flow_id": key,
            "sensor_id": ev["sensor_id"],
            "run": ev["run"],
            "event_id": ev["event_id"],
            "received_us": ev["received_us"],
            "event_time_us": ev["event_time_us"],
            "offset_us": ev["offset_us"],
            "obs_ms": ev["obs_ms"],
            "start_ms": start_ms,
            "coverage": ev["coverage"],
            "src": p["src_ip"], "dst": p["dst_ip"], "sport": p.get("src_port"), "dport": p.get("dst_port"),
            "proto": p["proto"], "service": p.get("service"),
            "new_flow": st is None,
            "terminal": terminal,
            "conn_state": p.get("conn_state") if terminal else None,
            "history": p.get("history"),
            "d": deltas,
            "total_orig_bytes": p.get("orig_bytes"),
            "total_resp_bytes": p.get("resp_bytes"),
            "duration_s": p.get("duration_s"),
        }
        if terminal:
            if st is not None:
                st_v.update({"term": True, "last_obs": ev["obs_ms"]})
                ctx.timer(_bucket_up(ev["obs_ms"] + self.tombstone_ms))
        else:
            merged = {c: max(prev.get(c) or 0, p[c]) if p.get(c) is not None else prev.get(c) for c in COUNTERS}
            st_v.update({"c": merged, "seq": p["snapshot_seq"], "term": False, "last_obs": ev["obs_ms"]})
            ctx.timer(_bucket_up(ev["obs_ms"] + self.idle_ms))
        return [("out", out)]

    def on_timer(self, ctx, key, ts):
        st_v = ctx.value("flow")
        st = st_v.value()
        if st is None:
            return []
        limit = self.tombstone_ms if st.get("term") else self.idle_ms
        if st["last_obs"] + limit <= ts:
            st_v.clear()
            ctx.metric("flow_state_expired")
        return []
