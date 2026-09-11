"""DNS detection: per-query lexical scoring (ONNX), per-(source, domain) tunnelling/DGA windows, and a
per-source NXDOMAIN burst detector that still works rules-only when no model is active.
"""
from __future__ import annotations

from sih_common import dga_features
from sih_common.iputil import is_ip
from sih_detect.alerts import SEVERITY_RANK, feature_record, finding, rate_limited
from sih_detect.common import append_ids, bucket_up, ev_min
from sih_detect.dga_model import DgaModel

VERSION_DGA = "dga-1.0.0"
VERSION_TUNNEL = "dns_tunnel-1.0.0"
VERSION_BURST = "dga_burst-1.0.0"
FSV_DNS = "dns_features-1.0.0"
TUNNEL_QTYPES = frozenset({"TXT", "NULL", "CNAME", "MX", "AAAA"})


class DnsScorer:
    """Stateless per-query processing with the locally loaded model."""

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory
        self.model = None
        self.fallback_table = dga_features.fit_bigram_table([])  # uniform; used only for rules-only features

    def open(self):
        self.model = DgaModel(self.cfg.model_root, self.cfg.dga_model_disable_after_errors)
        self.model.load()

    def observe(self, ev: dict) -> dict | None:
        p = ev["p"]
        q = p.get("query")
        obs = {"src": p["src_ip"], "query": q, "registrable": None, "sub": None, "vec": None, "p": None,
               "lex": None, "eligible": False, "reason": None, "nx": p.get("rcode_name") == "NXDOMAIN",
               "qtype": p.get("qtype_name"), "event_id": ev["event_id"], "obs_ms": ev["obs_ms"],
               "event_time_us": ev["event_time_us"], "offset_us": ev["offset_us"], "received_us": ev["received_us"],
               "sensor_id": ev["sensor_id"], "run": ev["run"], "coverage": ev["coverage"], "infer_s": 0.0,
               "model_version": None, "contrib": None}
        if q is None:
            obs["reason"] = "query_unavailable"
            return obs
        if self.inv.domain_allowlisted(q) or is_ip(q.rstrip(".")):
            obs["reason"] = "allowlisted" if not is_ip(q.rstrip(".")) else "not_registrable"
            return obs
        try:
            name = dga_features.normalize_name(q)
            registrable, _sld, _suffix, sub = dga_features.split_registrable(name)
            obs["registrable"] = registrable
            obs["sub"] = ".".join(sub) if sub else None
        except dga_features.NotEligible as e:
            obs["reason"] = e.reason
            return obs
        table = self.model.bigram_table if self.model.active else self.fallback_table
        try:
            vec, _info = dga_features.extract(q, table)
        except dga_features.NotEligible as e:
            obs["reason"] = e.reason
            return obs
        obs["vec"] = vec
        obs["lex"] = dga_features.lexical_rule(vec)
        if self.model.active:
            score, secs = self.model.score(vec)
            obs["infer_s"] = secs
            if score is not None:
                obs["p"], obs["eligible"], obs["model_version"] = score, True, self.model.version
                if score >= self.model.threshold:
                    obs["contrib"] = self.model.contributions(vec)
            else:
                obs["reason"] = "model_error"
        else:
            obs["reason"] = "model_unavailable"
        return obs


def _label_entropy(s: str) -> float:
    return dga_features.entropy(s)


class DnsDomainLogic:
    """Key: src|registrable domain. Tumbling windows bound the unique-label set."""
    value_states = ("m",)
    map_states = ("labels",)

    def __init__(self, cfg, inventory, model_info: dict | None = None):
        self.cfg = cfg
        self.inv = inventory
        self.model_info = model_info or {}

    def open(self):
        pass

    def on_event(self, ctx, key, o):
        cfg = self.cfg
        win = o["obs_ms"] // cfg.dns_window_ms
        mv, labels = ctx.value("m"), ctx.map("labels")
        m = mv.value()
        if m is None or m["win"] != win:
            labels.clear()
            m = {"win": win, "n": 0, "uniq": 0, "capped": False, "len_sum": 0, "ent_sum": 0.0, "name_bytes": 0,
                 "tunnel_qtypes": 0, "nx": 0, "first": ev_min(o), "ids": [], "rank_t": -1, "rank_d": -1}
        m["n"] += 1
        m["name_bytes"] += len(o["query"] or "")
        m["nx"] += 1 if o["nx"] else 0
        m["tunnel_qtypes"] += 1 if o["qtype"] in TUNNEL_QTYPES else 0
        sub = o["sub"]
        if sub:
            if labels.contains(sub):
                pass
            elif m["uniq"] >= cfg.dns_label_cap:
                m["capped"] = True
            else:
                labels.put(sub, 1)
                m["uniq"] += 1
                m["len_sum"] += len(sub)
                m["ent_sum"] += _label_entropy(sub.replace(".", ""))
        m["ids"] = append_ids(m["ids"], o["event_id"])
        m["last"] = ev_min(o)
        src, domain = o["src"], o["registrable"]
        mean_len = m["len_sum"] / m["uniq"] if m["uniq"] else None
        mean_ent = m["ent_sum"] / m["uniq"] if m["uniq"] else None
        out = []
        win_start = win * cfg.dns_window_ms
        if (m["uniq"] >= cfg.tunnel_min_unique_labels and mean_len >= cfg.tunnel_min_mean_label_len
                and mean_ent >= cfg.tunnel_min_mean_entropy):
            sev = "high" if m["uniq"] >= 5 * cfg.tunnel_min_unique_labels or m["name_bytes"] >= 20_000 else "medium"
            rank = SEVERITY_RANK[sev]
            if rank > m["rank_t"]:
                m["rank_t"] = rank
                out.append(("out", finding(
                    detector="dns", threat_class="dns_tunnel", subtype="dns_tunnel_like", entity_type="src_domain",
                    entity_key=key, severity=sev,
                    score=min(1.0, 0.4 + 0.3 * min(1, m["uniq"] / (4 * cfg.tunnel_min_unique_labels))
                              + 0.3 * min(1, (mean_ent or 0) / 4.5)),
                    method="rule", detector_version=VERSION_TUNNEL, feature_schema_version=FSV_DNS,
                    first=m["first"], last=m["last"], window_start_ms=win_start, window_end_ms=o["obs_ms"],
                    observed={"queries": m["n"], "unique_subdomains": m["uniq"], "mean_subdomain_len": mean_len,
                              "mean_subdomain_entropy": mean_ent, "query_name_bytes": m["name_bytes"],
                              "tunnel_qtype_queries": m["tunnel_qtypes"], "registrable_domain": domain},
                    thresholds={"min_unique_subdomains": cfg.tunnel_min_unique_labels,
                                "min_mean_len": cfg.tunnel_min_mean_label_len, "min_mean_entropy": cfg.tunnel_min_mean_entropy,
                                "window_s": cfg.dns_window_ms / 1000},
                    capped=["unique_subdomains"] if m["capped"] else [], coverage=o["coverage"], src_ip=src,
                    protocol="udp", raw_event_ids=m["ids"], evidence_count=m["n"],
                    top_features=[("unique_subdomains", m["uniq"], None, "count"), ("mean_subdomain_len", mean_len, None, "chars"),
                                  ("mean_subdomain_entropy", mean_ent, None, "bits/char")],
                    explanation=(f"{src} sent {m['n']} queries under {domain} with {m['uniq']} distinct subdomain strings "
                                 f"(mean length {mean_len:.1f}, mean entropy {mean_ent:.2f} bits/char) within the current "
                                 f"{cfg.dns_window_ms // 1000}s window. High-entropy unique labels are consistent with data "
                                 "encoded in DNS names."))))
        if o["p"] is not None and o["p"] >= self.model_info.get("threshold", 1.1):
            sev = "medium" if o["nx"] else "low"
            rank = SEVERITY_RANK[sev]
            if rank > m["rank_d"]:
                m["rank_d"] = rank
                contrib = o["contrib"] or []
                out.append(("out", finding(
                    detector="dns", threat_class="dga", subtype="dga_domain", entity_type="src_domain", entity_key=key,
                    severity=sev, score=o["p"], method="model", model_version=o["model_version"],
                    calibration_status=self.model_info.get("calibration_status", "uncalibrated"),
                    confidence_kind=self.model_info.get("confidence_kind", "heuristic_score"),
                    model_eligible=True, detector_version=VERSION_DGA, feature_schema_version=dga_features.FEATURE_SCHEMA_VERSION,
                    first=m["first"], last=m["last"], window_start_ms=win_start, window_end_ms=o["obs_ms"],
                    observed={"query": (o["query"] or "")[:255], "registrable_domain": domain, "nxdomain": o["nx"],
                              "model_score": o["p"]},
                    thresholds={"decision_threshold": self.model_info.get("threshold")},
                    coverage=o["coverage"], src_ip=src, protocol="udp", raw_event_ids=[o["event_id"]], evidence_count=1,
                    top_features=contrib,
                    explanation=(f"Model {o['model_version']} scored the name {domain} at {o['p']:.3f} "
                                 f"(threshold {self.model_info.get('threshold')}); the score is "
                                 f"{self.model_info.get('calibration_status', 'uncalibrated')}, not a verified probability."
                                 + (" The resolver answered NXDOMAIN." if o["nx"] else "")))))
        if (m["uniq"] >= cfg.tunnel_min_unique_labels // 2 or (o["p"] or 0) >= 0.5) and rate_limited(m, o["obs_ms"], cfg.feature_min_interval_ms):
            out.append(("feature", feature_record(
                "dns", FSV_DNS, "src_domain", key, o["sensor_id"], win_start, o["obs_ms"],
                {"queries": m["n"], "unique_subdomains": m["uniq"], "mean_subdomain_len": mean_len,
                 "mean_subdomain_entropy": mean_ent, "query_name_bytes": m["name_bytes"], "nxdomain_queries": m["nx"],
                 "dga_score": o["p"]},
                {"mean_subdomain_len": "NOT_APPLICABLE", "mean_subdomain_entropy": "NOT_APPLICABLE",
                 "dga_score": "UNKNOWN" if o["reason"] in (None, "model_error", "model_unavailable") else "NOT_APPLICABLE"},
                ["unique_subdomains"] if m["capped"] else [])))
        mv.update(m)
        ctx.timer(bucket_up((win + 1) * cfg.dns_window_ms, cfg.dns_window_ms))
        return out

    def on_timer(self, ctx, key, ts):
        mv = ctx.value("m")
        m = mv.value()
        if m is not None and (m["win"] + 1) * self.cfg.dns_window_ms < ts:
            mv.clear()
            ctx.map("labels").clear()
        return []


class DgaBurstLogic:
    """Key: source host. Distinct NXDOMAIN registrable domains per tumbling window and how many look
    algorithmically generated (model score >= 0.5 when active, lexical rule otherwise)."""
    value_states = ("m",)
    map_states = ("domains",)

    def __init__(self, cfg, inventory):
        self.cfg = cfg
        self.inv = inventory

    def open(self):
        pass

    def on_event(self, ctx, src, o):
        cfg = self.cfg
        if not o["nx"] or not o["registrable"]:
            return []
        win = o["obs_ms"] // cfg.dns_window_ms
        mv, doms = ctx.value("m"), ctx.map("domains")
        m = mv.value()
        if m is None or m["win"] != win:
            doms.clear()
            m = {"win": win, "nx": 0, "dga_like": 0, "capped": False, "first": ev_min(o), "ids": [], "rank": -1,
                 "model_version": None, "scored": 0, "rule_only": 0}
        dom = o["registrable"]
        if not doms.contains(dom):
            if m["nx"] >= cfg.dga_burst_domain_cap:
                m["capped"] = True
            else:
                if o["p"] is not None:
                    like = o["p"] >= 0.5
                    m["scored"] += 1
                    m["model_version"] = o["model_version"]
                else:
                    like = bool(o["lex"])
                    m["rule_only"] += 1
                doms.put(dom, 1 if like else 0)
                m["nx"] += 1
                m["dga_like"] += 1 if like else 0
                m["ids"] = append_ids(m["ids"], o["event_id"])
        m["last"] = ev_min(o)
        out = []
        if m["nx"] >= cfg.dga_burst_min_nx_domains and m["dga_like"] >= cfg.dga_burst_min_dga_like:
            rank = SEVERITY_RANK["high"]
            if rank > m["rank"]:
                m["rank"] = rank
                hybrid = m["model_version"] is not None
                out.append(("out", finding(
                    detector="dns", threat_class="dga", subtype="dga_nxdomain_burst", entity_type="src_host", entity_key=src,
                    severity="high", score=m["dga_like"] / max(1, m["nx"]), method="hybrid" if hybrid else "rule",
                    model_version=m["model_version"] if hybrid else None, model_eligible=hybrid,
                    model_reason=None if hybrid else "model_unavailable",
                    detector_version=VERSION_BURST, feature_schema_version=FSV_DNS, first=m["first"], last=m["last"],
                    window_start_ms=win * cfg.dns_window_ms, window_end_ms=o["obs_ms"],
                    observed={"nxdomain_domains": m["nx"], "dga_like_domains": m["dga_like"], "model_scored": m["scored"],
                              "rule_scored": m["rule_only"]},
                    thresholds={"min_nxdomain_domains": cfg.dga_burst_min_nx_domains,
                                "min_dga_like": cfg.dga_burst_min_dga_like, "window_s": cfg.dns_window_ms / 1000},
                    capped=["nxdomain_domains"] if m["capped"] else [], coverage=o["coverage"], src_ip=src, protocol="udp",
                    raw_event_ids=m["ids"], evidence_count=m["nx"],
                    top_features=[("nxdomain_domains", m["nx"], None, "count"), ("dga_like_domains", m["dga_like"], None, "count")],
                    explanation=(f"{src} received NXDOMAIN for {m['nx']} distinct registrable domains in "
                                 f"{cfg.dns_window_ms // 1000}s; {m['dga_like']} look algorithmically generated "
                                 f"({'model' if hybrid else 'lexical rule, model unavailable'})."))))
        mv.update(m)
        ctx.timer(bucket_up((win + 1) * cfg.dns_window_ms, cfg.dns_window_ms))
        return out

    def on_timer(self, ctx, src, ts):
        mv = ctx.value("m")
        m = mv.value()
        if m is not None and (m["win"] + 1) * self.cfg.dns_window_ms < ts:
            mv.clear()
            ctx.map("domains").clear()
        return []
