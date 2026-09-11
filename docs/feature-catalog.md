# Feature catalog

Every value below is computed in observation time (`docs/contracts.md`). Settings are candidate defaults
from `flink/sih_detect/config.py`, and each can be overridden with an `SIH_<NAME>` environment variable on the
job supervisor. They are tuned to the demo fixtures and are not universal detection guarantees.
"Unavailable" means the feature is `null`, with the listed availability state, in `features.v1` and in the alert
evidence. It is never replaced by zero.

## Flow deltas (all flow-based detectors)

| Item | Definition |
|---|---|
| Key | `sensor_id|sensor_boot_id|replay_run_id|uid` |
| Input | `flow_update` (cumulative snapshots every 5 s of payload-carrying live connections, capped at 2000/s by the sensor) and terminal `conn` |
| Delta | `current − previous` per counter (`orig/resp_bytes`, `orig/resp_pkts`). A decrease is a `flow_counter_regression` quality event, counted as 0 and never negative. The terminal conn adds only the remainder. |
| New flow | First record seen for the key |
| Late / duplicate | A snapshot with `snapshot_seq ≤ last`, or after the terminal record, is dropped and counted |
| State bound | Per flow: last counters plus sequence. Idle expiry after 10 min (`flow_idle_ms`). Terminal tombstone for 60 s. Short flows that only ever produce a terminal conn keep no state. |
| Availability | A counter unavailable in the source stays `null` in the delta. With `originator_only` or `responder_only` coverage, the unobserved direction is `UNKNOWN` (sender side). |

## Scan (`detect-scan`, key: source host, feature schema `scan_features-1.0.0`)

| Feature | Unit | Formula / window | Availability |
|---|---|---|---|
| `distinct_pairs` | count | Distinct (dst, port/proto) first-contacted within `scan_horizon_ms` (30 s) | Capped at `scan_pair_cap` (4096) → listed in `capped` (lower bound) |
| `distinct_hosts`, `distinct_ports` | count | Distinct destinations / port-protocol keys among live pairs | Same cap |
| `hosts_on_port` | count | Distinct hosts contacted on the current record's port | — |
| `ports_on_host` | count | Distinct ports contacted on the current record's host | — |
| `failed_ratio` | ratio | Terminal new flows in {S0, REJ, RSTOS0, SH} / terminal new flows with a known state | `UNKNOWN` unless coverage is `both_directions` and at least one outcome is known |

Rules: horizontal when `hosts_on_port ≥ 20`; vertical when `ports_on_host ≥ 25`. Severity is medium, or high at 5× the threshold or with a failed ratio ≥ 0.8 at 2×. Sources listed as authorized scanners in the inventory are downgraded to info. Score = `min(1, 0.5 + 0.5·count/(4·thr))` (heuristic, uncalibrated). Expiry timer every 5 s.

## Flood (`detect-ddos`, key: destination host, `ddos_features-1.0.0`)

| Feature | Unit | Formula / window | Availability |
|---|---|---|---|
| `flows_per_s` | 1/s | New flows in the current 1 s bucket | — |
| `syn_only_per_s` | 1/s | New terminal TCP flows with `conn_state = S0` | — |
| `bytes_per_s`, `pkts_per_s` | B/s, 1/s | Sum of available deltas in the bucket | `UNKNOWN` if any contributing delta was unavailable |
| `distinct_sources_5s` | count | Source cardinality over 5 buckets: exact up to 64 sources, then HyperLogLog (256 registers, ~6.5 % s.e.) | `capped` when estimated |
| `flows_per_source_5s` | ratio | 5 s flows / distinct sources | — |
| `amp_bytes_per_s`, `amp_sources_5s` | B/s, count | UDP from ports {19, 53, 111, 123, 137, 161, 389, 1900, 3702, 5353, 11211} | — |
| `baseline_flows_mean/std` | 1/s | EWMA (α 0.05) over closed, non-anomalous active seconds | `MISSING` during warm-up (30 buckets) |

Subtypes, in priority order:
1. `udp_amplification_like`: ≥ 500 kB/s amplification bytes and ≥ 10 reflectors in 5 s.
2. `spoofed_source_like_flood`: ≥ 500 sources in 5 s, ≤ 1.5 flows per source and ≥ half the flow threshold.
3. `syn_flood`: ≥ 100 SYN-only/s that make up ≥ 80 % of new flows.
4. `volumetric_flood`: `flows_per_s ≥ max(200, mean + 6·std)` or `bytes_per_s ≥ max(20 MB/s, …)`.

Severity is high, or critical at ≥ 10× the threshold. The names describe observations: many single-SYN sources are consistent with spoofing but do not prove it. Ten buckets are retained per destination, with idle expiry after 2 min.

## Beaconing (`detect-beacon`, key: src|dst|dst_port|proto, `beacon_features-1.0.0`)

| Feature | Unit | Formula | Availability |
|---|---|---|---|
| `connections` | count | Connection start times retained (last 64) | — |
| `median_iat_s` | s | Median inter-arrival time | — |
| `iat_robust_cv` | ratio | 1.4826·MAD(IAT)/median(IAT) | Only computed when the median is ≥ 5 s |
| `span_s` | s | Last start − first start | — |
| `size_robust_cv` | ratio | Robust CV of originator bytes of terminal flows | `UNKNOWN` with fewer than 4 sizes |
| `dst_external`, `known_periodic` | 0/1 | Asset inventory context | — |

Periodic when there are ≥ 8 connections, CV ≤ 0.15 and span ≥ 3·median. Pairs listed as known periodic in the inventory (OT polling, NTP) are suppressed and counted. Severity is medium for external destinations (high at CV ≤ 0.05 with ≥ 16 connections) and low for internal ones. A beacon of period P needs about 8·P of observation before it can alert. State expires after max(4·median, 10 min) without a new connection.

## DNS (`dns-score`, `detect-dns-domain`, `detect-dga-burst`, `dns_features-1.0.0`)

DGA lexical features (`dga_lexical-1.0.0`, 46 values) are specified in `schemas/features/dga_lexical.v1.json` and implemented in `lib/sih_common/dga_features.py`. The model abstains with a reason when the query is unavailable, the name is not registrable (single label, internal suffixes, `arpa`, IP literal), the SLD is shorter than 6 characters or the domain is allowlisted.

| Feature (key src|registrable domain, 60 s tumbling window) | Unit | Formula | Availability |
|---|---|---|---|
| `queries`, `nxdomain_queries` | count | Queries and NXDOMAIN responses in the window | — |
| `unique_subdomains` | count | Distinct subdomain strings left of the registrable domain | Capped at 1024 → `capped` |
| `mean_subdomain_len` | chars | Mean length over unique subdomains | `NOT_APPLICABLE` when there are none |
| `mean_subdomain_entropy` | bits/char | Mean Shannon entropy over unique subdomains | `NOT_APPLICABLE` when there are none |
| `query_name_bytes` | B | Sum of query-name lengths | — |
| `dga_score` | score | Model output for the latest query | `UNKNOWN` (model error/unavailable) or `NOT_APPLICABLE` (ineligible name) |

- Tunnel rule: ≥ 30 unique subdomains, mean length ≥ 20 and mean entropy ≥ 3.3. Severity is medium, or high at 5× or ≥ 20 kB of names per window.
- DGA domain: model score ≥ the manifest's decision threshold. Severity is low, or medium with NXDOMAIN. Method `model`. The confidence kind comes from the manifest (`heuristic_score`, `simulation_only`).
- NXDOMAIN burst (key src, 60 s): ≥ 10 distinct NXDOMAIN registrable domains of which ≥ 5 look generated. With the model active a domain counts at score ≥ 0.5 and the method is `hybrid`. Without the model the lexical rule applies (length ≥ 10, entropy ≥ 3.3 and digit ratio ≥ 0.2 or consonant run ≥ 4) and the method is `rule`. Distinct domains are capped at 512.

## Encrypted-session metadata (`detect-encrypted`, key src|dst|dst_port, `tls_features-1.0.0`)

| Indicator | Weight | Observable when |
|---|---|---|
| `old_tls_version` (SSLv2/3, TLS 1.0/1.1) | 0.30 | Handshake version logged |
| `sni_absent` | 0.25 | Handshake seen and `server_name` MISSING (`not_sent_by_client`) |
| `sni_ip_literal` | 0.20 | SNI present |
| `certificate_not_validated` | 0.25 | `validation_status` logged (not for TLS 1.3, where certificates are encrypted) |
| `nonstandard_port` | 0.10 | Destination port known |
| `dst_external` | 0.10 | Always (inventory) |

Score = weight of positive indicators / weight of observable indicators. The detector abstains, with a metric and `UNKNOWN` features, when fewer than 3 indicators are observable. It alerts when the best score is ≥ 0.6 with ≥ 2 positives over ≥ 3 scored sessions within 30 min. Severity is low, or medium at ≥ 10 sessions to an external destination. Handshake metadata only; the score is not a malware verdict.

## Exfiltration (`detect-exfil`, key local source host, `exfil_features-1.0.0`)

Only local → external flows, excluding inventory `known_bulk_transfer` pairs, with available originator bytes.

| Feature | Unit | Formula | Availability |
|---|---|---|---|
| `outbound_bytes_window` | B | Sum of originator deltas in the last 30 s | — |
| `inbound_bytes_window` | B | Sum of responder deltas | `UNKNOWN` unless every contributing record had both directions observed |
| `out_in_ratio` | ratio | Outbound / inbound | `UNKNOWN` when inbound is unknown or 0 |
| `span_s`, `records` | s, count | Time between the first and last contributing record; record count (≤ 2048) | — |
| `baseline_window_bytes_mean` | B | EWMA (α 0.1) of previous non-anomalous 30 s windows | `MISSING` for the first 6 windows |

Sustained upload when outbound ≥ max(10 MB, 10·baseline), span ≥ 15 s and ≥ 3 records. Severity is medium, or high at ≥ 5× or for a first-seen destination at ≥ 2×. Destination rarity uses a per-source map capped at 256 entries. State expires after 10 min idle.

## Incident correlation (`incident`, key threat_class|entity_type|entity_key)

- `incident_id = UUIDv5(class|entity type|entity key|first window start floored to 1 s)`, and `update_id = UUIDv5(incident_id|update_seq)`.
- A new incident emits `new`. A higher severity emits `escalated` immediately, as does a new subtype (for example `syn_flood` refined to `spoofed_source_like_flood`) as an `updated`. The same severity with more evidence emits `updated` at most once per 60 s. The incident is `resolved` after 5 min idle (30 min for beaconing).
- Evidence keeps up to 32 raw event IDs, with a truncation flag and the full evidence count.
