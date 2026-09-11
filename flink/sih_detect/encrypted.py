"""Encrypted-session metadata detector. Key: src|dst|dst_port.

Uses only TLS handshake metadata that Zeek logs without decryption. Each indicator is scored only when its
field is available; with too few available indicators the detector abstains. The score is heuristic and
describes metadata suspicion, not malware.
"""
from __future__ import annotations

from sih_common.iputil import is_ip
from sih_detect.alerts import SEVERITY_RANK, feature_record, finding, rate_limited
from sih_detect.common import append_ids, bucket_up, ev_min

VERSION = "encrypted-1.0.0"
FSV = "tls_features-1.0.0"
OLD_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv10", "TLSv11"})
STANDARD_TLS_PORTS = frozenset({443, 465, 563, 636, 853, 989, 990, 993, 995, 4843, 5061, 8443, 8883})
WEIGHTS = {"old_tls_version": 0.3, "sni_absent": 0.25, "sni_ip_literal": 0.2, "nonstandard_port": 0.1,
           "certificate_not_validated": 0.25, "dst_external": 0.1}


def indicators(p: dict, a: dict, dst_external: bool) -> dict:
    """name -> True/False when observable, None when unavailable."""
    ind = dict.fromkeys(WEIGHTS)
    handshake_seen = p.get("version") is not None
    if handshake_seen:
        ind["old_tls_version"] = p["version"] in OLD_VERSIONS
    sni = p.get("server_name")
    if sni is not None:
        ind["sni_absent"] = False
        ind["sni_ip_literal"] = is_ip(sni)
    elif handshake_seen and a.get("server_name") == "MISSING":
        ind["sni_absent"] = True
        ind["sni_ip_literal"] = False
    if p.get("dst_port") is not None:
        ind["nonstandard_port"] = p["dst_port"] not in STANDARD_TLS_PORTS
    vs = p.get("validation_status")
    if vs is not None:
        ind["certificate_not_validated"] = vs.strip().lower() != "ok"
    ind["dst_external"] = dst_external
    return ind


class EncryptedLogic:
    value_states = ("s",)
    map_states = ()

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory

    def open(self):
        pass

    def on_event(self, ctx, key, ev):
        cfg = self.cfg
        p, a = ev["p"], ev["a"]
        ind = indicators(p, a, not self.inv.is_local(p["dst_ip"]))
        avail = {k: v for k, v in ind.items() if v is not None}
        sv = ctx.value("s")
        s = sv.value()
        if s is None or ev["obs_ms"] > s["last"]["obs_ms"] + cfg.tls_horizon_ms:
            s = {"sessions": 0, "scored": 0, "max_score": 0.0, "max_pos": 0, "first": ev_min(ev), "ids": [], "rank": -1}
        s["sessions"] += 1
        s["last"] = ev_min(ev)
        s["ids"] = append_ids(s["ids"], ev["event_id"])
        out = []
        unavailable = sorted(k for k, v in ind.items() if v is None)
        if len(avail) < cfg.tls_min_available:
            ctx.metric("tls_abstained")
            score, positives = None, 0
        else:
            aw = sum(WEIGHTS[k] for k in avail)
            positives = [k for k, v in avail.items() if v]
            score = sum(WEIGHTS[k] for k in positives) / aw
            s["scored"] += 1
            if score >= s["max_score"]:
                s["max_score"], s["max_pos"], s["positives"] = score, len(positives), positives
        if (s["scored"] >= cfg.tls_min_sessions and s["max_score"] >= cfg.tls_min_score
                and s["max_pos"] >= cfg.tls_min_positive):
            external = bool(ind["dst_external"])
            sev = "medium" if s["sessions"] >= 10 and external else "low"
            rank = SEVERITY_RANK[sev]
            if rank > s["rank"]:
                s["rank"] = rank
                pos = s.get("positives", [])
                out.append(("out", finding(
                    detector="encrypted", threat_class="encrypted_malware_like", subtype="suspicious_tls_metadata",
                    entity_type="service_pair", entity_key=key, severity=sev, score=s["max_score"], method="rule",
                    detector_version=VERSION, feature_schema_version=FSV, first=s["first"], last=s["last"],
                    window_start_ms=s["first"]["obs_ms"], window_end_ms=ev["obs_ms"],
                    observed={"sessions": s["sessions"], "scored_sessions": s["scored"], "max_score": s["max_score"],
                              "tls_version": p.get("version"), "server_name": p.get("server_name"),
                              "validation_status": p.get("validation_status"),
                              **{f"ind_{k}": v for k, v in ind.items()}},
                    thresholds={"min_score": cfg.tls_min_score, "min_positive": cfg.tls_min_positive,
                                "min_sessions": cfg.tls_min_sessions, "min_available": cfg.tls_min_available},
                    unavailable=unavailable, coverage=ev["coverage"], src_ip=p["src_ip"], dst_ip=p["dst_ip"],
                    dst_port=p.get("dst_port"), protocol="tcp", raw_event_ids=s["ids"], evidence_count=s["sessions"],
                    top_features=[(k, 1, WEIGHTS[k], "indicator") for k in pos][:10],
                    explanation=(f"{s['sessions']} TLS sessions from {p['src_ip']} to {p['dst_ip']}:{p.get('dst_port')} "
                                 f"show metadata indicators: {', '.join(pos) or 'none'}. Unobservable indicators: "
                                 f"{', '.join(unavailable) or 'none'}. Handshake metadata only; no payload was decrypted "
                                 "and this is not a malware verdict."))))
        if score is not None and score >= cfg.tls_min_score / 2 and rate_limited(s, ev["obs_ms"], cfg.feature_min_interval_ms):
            values = {"sessions": s["sessions"], "score": score, **{k: (1 if v else 0) if v is not None else None for k, v in ind.items()}}
            out.append(("feature", feature_record("encrypted", FSV, "service_pair", key, ev["sensor_id"],
                                                  s["first"]["obs_ms"], ev["obs_ms"], values,
                                                  {k: "UNKNOWN" for k in unavailable})))
        sv.update(s)
        ctx.timer(bucket_up(ev["obs_ms"] + cfg.tls_horizon_ms, 60_000))
        return out

    def on_timer(self, ctx, key, ts):
        sv = ctx.value("s")
        s = sv.value()
        if s is not None and s["last"]["obs_ms"] + self.cfg.tls_horizon_ms <= ts:
            sv.clear()
        return []
