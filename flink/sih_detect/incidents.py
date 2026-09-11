"""Incident correlation: deterministic incident/update IDs, cooldown, escalation and idle resolution.

Key: threat_class|entity_type|entity_key. A stronger finding escalates immediately; repeated findings
at the same severity update at most once per cooldown and only when the evidence grew; the incident
resolves after an idle period in observation time. Replays from a checkpoint reproduce the same
update IDs, so downstream consumers deduplicate them.
"""
from __future__ import annotations

from sih_common import ids
from sih_detect.alerts import SEVERITY_RANK, alert_record


def _bucket_up(ts_ms: int, step: int = 10_000) -> int:
    return (ts_ms // step + 1) * step


class IncidentLogic:
    value_states = ("incident",)
    map_states = ()

    def __init__(self, cfg):
        self.cooldown = cfg.incident_cooldown_ms
        self.idle = cfg.incident_idle_ms
        self.idle_beacon = cfg.incident_idle_beacon_ms

    def open(self):
        pass

    def _idle_for(self, threat_class: str) -> int:
        return self.idle_beacon if threat_class == "beaconing" else self.idle

    def on_event(self, ctx, key, f):
        st_v = ctx.value("incident")
        st = st_v.value()
        idle = self._idle_for(f["threat_class"])
        out = []
        if st is not None and f["obs_ms"] > st["last_obs"] + idle:
            out += self._resolve(st)  # the watermark lagged behind the idle timer
            st = None
        rank = SEVERITY_RANK[f["severity"]]
        if st is None:
            epoch = (f["window_start_ms"] // 1000) * 1000
            inc = ids.incident_id(f["threat_class"], f["entity_type"], f["entity_key"], epoch)
            st = {"id": inc, "seq": 1, "rank": rank, "last_emit": f["obs_ms"], "last_obs": f["obs_ms"],
                  "count": f["evidence_count"], "emitted_count": f["evidence_count"], "first": f["first_seen_ms"],
                  "window_start": f["window_start_ms"], "ids": list(f["raw_event_ids"]), "last": f,
                  "subtypes": [f["subtype"]]}
            out.append(("out", alert_record(self._merged(st, f), inc, 1, "new")))
            ctx.metric("incidents_opened")
        else:
            st["last_obs"] = max(st["last_obs"], f["obs_ms"])
            st["count"] = max(st["count"], f["evidence_count"])
            st["ids"] = (st["ids"] + [i for i in f["raw_event_ids"] if i not in st["ids"]])[-32:]
            st["last"] = f
            new_subtype = f["subtype"] not in st.setdefault("subtypes", [])
            if new_subtype:
                st["subtypes"] = (st["subtypes"] + [f["subtype"]])[-8:]
            if rank > st["rank"]:
                st["seq"] += 1
                st["rank"] = rank
                st["last_emit"] = f["obs_ms"]
                st["emitted_count"] = st["count"]
                out.append(("out", alert_record(self._merged(st, f), st["id"], st["seq"], "escalated")))
                ctx.metric("incidents_escalated")
            elif new_subtype:
                # A refined classification (e.g. syn_flood -> spoofed_source_like_flood) is reported at once.
                st["seq"] += 1
                st["last_emit"] = f["obs_ms"]
                st["emitted_count"] = st["count"]
                out.append(("out", alert_record(self._merged(st, f), st["id"], st["seq"], "updated")))
            elif f["obs_ms"] - st["last_emit"] >= self.cooldown and st["count"] > st["emitted_count"]:
                st["seq"] += 1
                st["last_emit"] = f["obs_ms"]
                st["emitted_count"] = st["count"]
                out.append(("out", alert_record(self._merged(st, f), st["id"], st["seq"], "updated")))
            else:
                ctx.metric("findings_suppressed")
        st_v.update(st)
        ctx.timer(_bucket_up(st["last_obs"] + idle))
        return out

    def _merged(self, st: dict, f: dict) -> dict:
        """The finding as seen by the incident: evidence accumulated over the incident's lifetime."""
        m = dict(f)
        m["raw_event_ids"] = st["ids"]
        m["evidence_count"] = max(st["count"], len(st["ids"]))
        m["first_seen_ms"] = min(st["first"], f["first_seen_ms"])
        m["window_start_ms"] = min(st["window_start"], f["window_start_ms"])
        m["severity"] = _severity_of(st["rank"])  # an incident never de-escalates within its lifetime
        return m

    def _resolve(self, st: dict) -> list:
        st["seq"] += 1
        f = self._merged(st, st["last"])
        return [("out", alert_record(f, st["id"], st["seq"], "resolved"))]

    def on_timer(self, ctx, key, ts):
        st_v = ctx.value("incident")
        st = st_v.value()
        if st is None:
            return []
        if st["last_obs"] + self._idle_for(st["last"]["threat_class"]) <= ts:
            st_v.clear()
            ctx.metric("incidents_resolved")
            return self._resolve(st)
        return []


def _severity_of(rank: int) -> str:
    for name, r in SEVERITY_RANK.items():
        if r == rank:
            return name
    return "info"
