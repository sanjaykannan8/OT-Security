"""Detection configuration. Every field can be overridden by env var SIH_<FIELD_NAME_UPPER>.

The defaults are candidate settings for the demo fixtures, not universal detection guarantees; they are
listed with units in docs/feature-catalog.md.
"""
from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectConfig:
    kafka_bootstrap: str = "redpanda:9092"
    raw_topic: str = "raw-events.v1"
    alerts_topic: str = "alerts.v1"
    features_topic: str = "features.v1"
    invalid_topic: str = "invalid-events.v1"
    group_id: str = "flink-detection-v1"
    model_root: str = "/opt/sih/models"
    inventory_path: str = "/opt/sih/reference/asset-inventory.json"
    out_of_orderness_ms: int = 2000
    idleness_ms: int = 5000
    feature_min_interval_ms: int = 5000

    # flow delta
    flow_idle_ms: int = 600_000
    flow_tombstone_ms: int = 60_000

    # scan (key: source host)
    scan_horizon_ms: int = 30_000
    scan_host_threshold: int = 20        # distinct hosts on one port
    scan_port_threshold: int = 25        # distinct ports on one host
    scan_pair_cap: int = 4096

    # flood (key: destination host)
    ddos_min_flows_per_s: int = 200
    ddos_min_bytes_per_s: int = 20_000_000
    ddos_syn_min_per_s: int = 100
    ddos_spoof_min_sources_5s: int = 500
    ddos_amp_min_bytes_per_s: int = 500_000
    ddos_amp_min_reflectors_5s: int = 10
    ddos_baseline_k: float = 6.0
    ddos_warmup_buckets: int = 30
    ddos_episode_gap_ms: int = 30_000
    ddos_idle_ms: int = 120_000

    # beaconing (key: src/dst/port/proto)
    beacon_min_events: int = 8
    beacon_max_events: int = 64
    beacon_min_interval_ms: int = 5_000
    beacon_max_cv: float = 0.15

    # DNS
    dns_window_ms: int = 60_000
    dns_label_cap: int = 1024
    tunnel_min_unique_labels: int = 30
    tunnel_min_mean_label_len: float = 20.0
    tunnel_min_mean_entropy: float = 3.3
    dga_burst_min_nx_domains: int = 10
    dga_burst_min_dga_like: int = 5
    dga_burst_domain_cap: int = 512
    dga_model_disable_after_errors: int = 20

    # encrypted metadata (key: src/dst/port)
    tls_horizon_ms: int = 1_800_000
    tls_min_score: float = 0.6
    tls_min_positive: int = 2
    tls_min_available: int = 3
    tls_min_sessions: int = 3

    # exfiltration (key: source host)
    exfil_window_ms: int = 30_000
    exfil_min_bytes: int = 10_000_000     # per window; demo-scale candidate, tune per asset class
    exfil_min_span_ms: int = 15_000
    exfil_min_records: int = 3
    exfil_baseline_k: float = 10.0
    exfil_dst_cap: int = 256

    # incidents
    incident_cooldown_ms: int = 60_000
    incident_idle_ms: int = 300_000
    incident_idle_beacon_ms: int = 1_800_000

    @classmethod
    def from_env(cls) -> "DetectConfig":
        kwargs = {}
        for f in dataclasses.fields(cls):
            raw = os.environ.get("SIH_" + f.name.upper())
            if raw is None or raw.strip() == "":
                continue
            kwargs[f.name] = type(f.default)(raw.strip()) if not isinstance(f.default, bool) else raw.strip().lower() in ("1", "true")
        return cls(**kwargs)
