# Contracts to freeze before implementation

This document defines semantics. Phase 1 must turn them into strict versioned JSON Schemas, examples and validation tests before application code relies on them.

## Events

Required envelope fields: `event_schema_version`, `event_id`, `sensor_id`, `sensor_boot_id`, `sequence`, `log_type`, `event_time`, `sensor_emitted_at`, `receiver_received_at`, `capture_mode`, `observation_coverage`, `payload`.

- Schema versions are explicit strings, initially `1.0.0`.
- Timestamps are UTC with documented precision. Preserve original capture time and separate replay wall-clock timestamps. Do not subtract historical PCAP timestamps from current wall time for processing latency.
- `capture_mode`: `pcap_replay`, `synthetic_log`, or reserved `passive_live`.
- `observation_coverage`: `both_directions`, `originator_only`, `responder_only`, or `unknown`. Both directions is the default input expectation, not proof that no capture loss occurred.
- Event IDs derive deterministically from sensor/boot/sequence and original record identity. Persist sender identity and sequence across restart. A new scenario run gets a new replay run ID; restarting the same run preserves its identity.
- Scope Zeek UID with sensor and boot ID. Community ID is optional correlation data, not a universally unique event identifier.
- Retain an original-record hash and bounded original record for forensic correlation, subject to export policy.
- All input is size-limited and validated before expensive parsing. Quarantine incompatible schema versions and invalid values with reasons.

## Availability semantics

Each optional telemetry field has a value and availability state, either represented inline or in a versioned side map:

| State | Meaning |
|---|---|
| AVAILABLE | Valid observed value, including a genuine zero |
| MISSING | Expected for this record/capability, but absent |
| NOT_APPLICABLE | Does not apply, e.g. TLS version for a plain DNS UDP flow |
| UNKNOWN | Cannot determine validity/visibility, including unresolved direction or capture coverage |

Record reason codes when useful. A model may use trained imputation with indicators only if its manifest explicitly permits it. A required unavailable feature causes abstention, not invented evidence.

## Topics and consumers

| Topic | Producer | Independent consumers |
|---|---|---|
| `raw-events.v1` | Receiving-side publisher | `flink-detection-v1`, `raw-clickhouse-v1`, optional archive consumer |
| `features.v1` | Flink | `features-clickhouse-v1`, optional research export |
| `alerts.v1` | Flink incident logic | `alerts-clickhouse-v1`, `alerts-opensearch-v1`, `alerts-notifier-v1`, `alerts-live-api-v1` |
| `invalid-events.v1` | Receiver/Flink | Restricted quarantine persistence |
| `sensor-health.v1` | Receiving publisher from outward health telemetry | Metrics adapter and audit sink |

Default demo candidate: 3 raw partitions, replication factor 1; production-like: 3 brokers and RF3 with tested acknowledgement/minimum-replica behavior. Define all topics explicitly; disable accidental auto-creation where practical. Pin bounded retention and record disk budgets. Do not compact raw event topics. Consumer groups acknowledge offsets only after the required durable write succeeds.

## Features and state

Each feature catalog row must define name, scalar/vector type, unit, source, formula, window, key, availability rule, clipping/normalization, model consumers and explanation meaning.

Initial feature groups:

- Destination/service rates: packets, bytes, new flows, source cardinality, source entropy, protocol mix.
- Source scanning: unique destination hosts/ports, sequentiality, observed success/failure ratio.
- Source/destination/service beaconing: count, robust IAT dispersion, median IAT, persistence, size consistency.
- Source/registrable-domain DNS: length, entropy, digit ratio, n-grams, record types, unique labels, rates, observed NXDOMAIN ratio.
- Encrypted metadata: available TLS fields/fingerprints, visible QUIC header fields, bounded packet size/timing statistics.
- Asset exfiltration: outbound delta bytes, sustained rate, inbound/outbound ratio, baseline deviation and passive destination rarity.

Start with 1-second rate buckets, 5/30-second aggregate horizons and a configurable 5-minute beacon horizon. These are candidate settings, not universal detection guarantees. Slow-scan/exfiltration horizons may be longer but remain bounded. Avoid storing every packet or building unbounded per-IP sets. Specify per-key and total state budgets; use tested sketches where appropriate.

Periodic cumulative flow snapshots must be converted to deltas exactly once. Conn terminal summaries enrich/end the flow; they must not re-add all previous bytes or increment new-flow counts again. Reset/regression in counters is a quality event. Late duplicates cannot move counters backwards.

Event-time windows use an initial 2-second out-of-order allowance and 5-second partition-idleness candidate. Tune from replay measurements. Early alerts fire when sufficient evidence exists; they must not always wait for window closure. Record late-event behavior explicitly, including incident updates. Use event-time timers for semantic expiry and state TTL as additional cleanup, not as a replacement for event-time logic.

## Alerts and incident updates

Required fields: `alert_schema_version`, `alert_id`, `incident_id`, `update_id`, `timestamp`, `event_time`, `flow_id`, source/destination IP/port, protocol, threat class, severity, confidence, `confidence_kind`, model/detector version, feature-schema version, detection method, evidence, top features, window start/end, first/last seen, deduplication key and status.

- Protocol-dependent addresses/ports may be null with explicit semantics. Validate enums and bounds.
- `confidence_kind`: `calibrated_probability`, `heuristic_score`, or `unavailable`. Unknown confidence is null, never a fabricated probability.
- `model_version` is null for rules-only alerts; include `detector_version` always.
- Keep stable incident IDs and deterministic update IDs. A stronger observation updates/escalates an incident without paging once per packet.
- Bounded evidence references immutable raw-event IDs and includes actual observed values, thresholds, baseline context, visibility and model eligibility.
- Store incident updates append-only; expose the latest incident state separately. ClickHouse and OpenSearch must use explicit deduplication/upsert semantics; eventual table merges alone are not immediate deduplication.
- Notifier idempotency uses durable processed update IDs. External webhook exactly-once behavior cannot be guaranteed without recipient cooperation.

## Model bundle

Directory per threat and immutable version: `model.onnx`, `metadata.json`, `feature_schema.json`, checksum file, calibration parameters and training provenance. Only populate ONNX files for actually trained and tested models.

Manifest fields: threat, version, ordered inputs/dtypes/shapes, opset, native/runtime compatibility, preprocessing and feature version, required fields, missingness policy, output semantics, calibration version, dataset references/hashes, split method, evaluation metrics, creation time and checksum.

Use an explicit deployment manifest selecting versions. Startup validates, warms and records health before activation. Recoveries must reuse the selected version. Promotion/rollback changes a version reference and uses a controlled savepoint/redeploy procedure. No automatic downloads or registry calls in the hot path.

## Frozen implementation details (Phase 1, integration owner)

The machine-readable versions of everything below live in `schemas/`. Where this section and a schema disagree, the schema wins, and the disagreement is a bug to fix in both places.

### Schema files

| Schema | File | Topic / location |
|---|---|---|
| Event 1.0.0 | `schemas/event.v1.schema.json` | `raw-events.v1` |
| Alert (incident update) 1.0.0 | `schemas/alert.v1.schema.json` | `alerts.v1` |
| Feature snapshot 1.0.0 | `schemas/feature.v1.schema.json` | `features.v1` |
| Sensor health 1.0.0 | `schemas/sensor-health.v1.schema.json` | `sensor-health.v1` |
| Quarantined input 1.0.0 | `schemas/invalid-event.v1.schema.json` | `invalid-events.v1` |
| Model manifest 1.0.0 | `schemas/model-manifest.v1.schema.json` | `models/<threat>/<version>/metadata.json` |
| Deployment manifest 1.0.0 | `schemas/deployment-manifest.v1.schema.json` | `models/deployment.json` |

Cross-field rules that JSON Schema cannot express are implemented once in `lib/sih_common/contracts.py`, which the receiver, consumers, API and tests all use. The examples under `schemas/examples/` are the shared test vectors.

### Kafka record timestamps

The receiver sets each `raw-events.v1` record's Kafka timestamp to the record's observation time in milliseconds: `event_time + replay_time_offset_us`, plus `duration_s` for terminal `conn` records (a connection is observable when it ends). The Flink source uses these timestamps directly, so watermarks are generated per partition inside the Kafka source, before any Python code runs. Health and quarantine records use the producer's wall clock.

### Envelope additions

- `replay_run_id` (string or null) and `replay_time_offset_us` (integer) are required. **Observation time** = `event_time + replay_time_offset_us`. All Flink event-time logic (watermarks, windows, timers) uses observation time, so a historical PCAP replayed after a newer one is not dropped as late. `event_time` always remains the original capture time. The offset is constant for one replay run and is 0 in tail (live-like) mode.
- Availability uses a side map: every payload key is always present. A `null` value MUST have an `availability` entry (`MISSING`, `NOT_APPLICABLE` or `UNKNOWN`); a non-null value MUST NOT. `AVAILABLE` is implied by absence from the map, so a genuine zero is a non-null value with no entry. `availability_reasons` keys must be a subset of `availability` keys.
- `original_record` holds at most 4096 characters. When the original is longer, it is `null` and `original_record_truncated` is `true`; `original_record_sha256` is always the SHA-256 of the complete original line (UTF-8, without trailing newline).
- Timestamps are emitted as `YYYY-MM-DDTHH:MM:SS.ffffffZ` (exactly six fractional digits, UTC). Readers accept 0–6 fractional digits. Zeek `ts` is parsed from its decimal text (not via binary float) and rounded half-up to microseconds.

### Deterministic identifiers

All derived identifiers are UUIDv5 over the UTF-8 string of `|`-joined fields. Nulls are written as the empty string.

| Identifier | Namespace UUID | Name |
|---|---|---|
| `event_id` | `5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a01` | `sensor_id|sensor_boot_id|sequence|original_record_sha256` |
| `incident_id` | `5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a02` | `threat_class|entity.type|entity.key|incident_epoch_ms` |
| `update_id` | `5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a03` | `incident_id|update_seq` |
| `alert_id` | `5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a04` | `detector|entity.type|entity.key|window_end_ms|subtype` |
| `feature_record_id` | `5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a05` | `detector|entity.type|entity.key|window_end_ms` |
| `invalid_id` | `5d0c1c52-8a4e-4f0e-9a51-3e3b8f6f2a06` | `stage|reason_code|raw_sha256|sensor_id|sensor_boot_id|sequence` |

`incident_epoch_ms` is the observation time of the first evidence that opened the incident, floored to the detector bucket. Cross-language vectors are in `schemas/examples/id_vectors.json`.

### One-way link frame (sender → receiver)

UDP datagrams, big-endian, at most `MAX_DATAGRAM_BYTES = 1400`:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `SIH1` (0x53 0x49 0x48 0x31) |
| 4 | 1 | frame version = 1 |
| 5 | 1 | frame type: 1 = event envelope, 2 = sensor health |
| 6 | 1 | flags (reserved, 0) |
| 7 | 1 | fragment index (0-based) |
| 8 | 1 | fragment count (1–8) |
| 9 | 1 | sensor_id length L (1–63) |
| 10 | L | sensor_id (ASCII) |
| 10+L | 16 | sensor_boot_id (raw UUID bytes) |
| 26+L | 8 | sequence (event frames) or health_seq (health frames) |
| 34+L | 4 | total record length (≤ `MAX_RECORD_BYTES = 9600`) |
| 38+L | 2 | chunk length (≤ `MAX_CHUNK_BYTES = 1200`) |
| 40+L | n | chunk bytes (UTF-8 JSON fragment) |
| 40+L+n | 32 | HMAC-SHA256 over all preceding bytes, keyed with the locally provisioned link key |

- The event record on the link is the event envelope without `receiver_received_at`. The receiver adds that field and then validates the complete event against the schema. Health records likewise omit `received_at`.
- A record whose serialized envelope exceeds `MAX_RECORD_BYTES` is first retried with `original_record = null`, `original_record_truncated = true`. If it is still too large, the sender rejects it locally and counts it in `records_rejected_oversize_total`. IP fragmentation is never relied upon.
- Reassembly is bounded: at most 4096 incomplete records and a 2 s completion timeout. Overflow and timeout are counted and quarantined (`fragment_overflow`, `fragment_timeout`).
- Duplicate suppression uses a per-(sensor_id, sensor_boot_id) window of 65 536 sequences, persisted with the receiver spool. Gaps are counted when the window advances past a missing sequence. The sender may send each frame `LINK_REDUNDANCY` times (default 1). There is no acknowledgement, retransmission request or any other return traffic.

### Topic configuration (demo profile)

| Topic | Partitions | Key | retention.ms | retention.bytes (per partition) |
|---|---|---|---|---|
| `raw-events.v1` | 3 | `sensor_id|sensor_boot_id|replay_run_id|uid`, else `event_id` | 86 400 000 | 1 GiB |
| `features.v1` | 3 | none (round-robin) | 86 400 000 | 512 MiB |
| `alerts.v1` | 1 | none; the single partition keeps total order | 604 800 000 | 256 MiB |
| `invalid-events.v1` | 1 | `invalid_id` | 604 800 000 | 256 MiB |
| `sensor-health.v1` | 1 | `sensor_id` | 604 800 000 | 128 MiB |

All topics use `cleanup.policy=delete` and `message.timestamp.type=CreateTime`. Additional consumer groups beyond the table above: `invalid-clickhouse-v1` and `health-clickhouse-v1`.

The PyFlink Kafka sink cannot derive a record key from a field of the element. Alerts therefore go to a single partition, which preserves total order in the demo. Consumers never rely on keys: they deduplicate on `update_id`, and the latest incident state is selected by `update_seq`. A multi-partition production layout would add a keyed re-partitioning step before the sink.

### Schema evolution

See `schemas/README.md`. Summary: a payload or envelope change bumps the schema version. Additive optional fields bump the minor version, and anything else bumps the major version and gets a new topic (`*.v2`). Validators hold every supported minor version of the current major. An unsupported version is quarantined with reason `unsupported_schema_version`, never guessed.
