-- SIH26145 hot storage. Idempotent; applied by the clickhouse-init job on every start.
-- No unconditional TTL: partitions are removed only by the retention job after a verified archive
-- manifest exists (consumers/sih_consumers/archive.py). ReplacingMergeTree + FINAL/argMax give
-- immediate deduplication in queries; background merges are not relied upon for correctness.

CREATE DATABASE IF NOT EXISTS sih;

CREATE TABLE IF NOT EXISTS sih.schema_migrations
(
    version UInt32,
    applied_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(applied_at) ORDER BY version;

CREATE TABLE IF NOT EXISTS sih.raw_events
(
    event_id UUID,
    sensor_id LowCardinality(String),
    sensor_boot_id UUID,
    sequence UInt64,
    replay_run_id Nullable(String),
    log_type LowCardinality(String),
    event_time DateTime64(6, 'UTC'),
    observation_time DateTime64(3, 'UTC'),
    receiver_received_at DateTime64(6, 'UTC'),
    capture_mode LowCardinality(String),
    observation_coverage LowCardinality(String),
    uid Nullable(String),
    src_ip Nullable(String),
    src_port Nullable(UInt16),
    dst_ip Nullable(String),
    dst_port Nullable(UInt16),
    proto LowCardinality(Nullable(String)),
    event_json String CODEC(ZSTD(3)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    ingest_day Date DEFAULT toDate(receiver_received_at),
    INDEX idx_obs observation_time TYPE minmax GRANULARITY 4,
    INDEX idx_src src_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dst dst_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_event event_id TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY ingest_day
ORDER BY (sensor_id, event_id);

CREATE TABLE IF NOT EXISTS sih.features
(
    feature_record_id UUID,
    feature_schema_version LowCardinality(String),
    detector LowCardinality(String),
    entity_type LowCardinality(String),
    entity_key String,
    sensor_id LowCardinality(String),
    window_start DateTime64(3, 'UTC'),
    window_end DateTime64(3, 'UTC'),
    computed_at DateTime64(6, 'UTC'),
    feature_values Map(String, Float64),
    availability Map(String, String),
    capped Array(String),
    record_json String CODEC(ZSTD(3)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    ingest_day Date DEFAULT toDate(ingested_at)
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY ingest_day
ORDER BY (detector, entity_key, feature_record_id);

CREATE TABLE IF NOT EXISTS sih.alert_updates
(
    update_id UUID,
    incident_id UUID,
    alert_id UUID,
    update_seq UInt32,
    status LowCardinality(String),
    ts DateTime64(6, 'UTC'),
    event_time DateTime64(6, 'UTC'),
    observation_time DateTime64(3, 'UTC'),
    evidence_received_at DateTime64(6, 'UTC'),
    sensor_id LowCardinality(String),
    replay_run_id Nullable(String),
    threat_class LowCardinality(String),
    subtype LowCardinality(String),
    severity LowCardinality(String),
    confidence Nullable(Float64),
    confidence_kind LowCardinality(String),
    calibration_status LowCardinality(String),
    model_version Nullable(String),
    detector_version LowCardinality(String),
    detection_method LowCardinality(String),
    entity_type LowCardinality(String),
    entity_key String,
    src_ip Nullable(String),
    src_port Nullable(UInt16),
    dst_ip Nullable(String),
    dst_port Nullable(UInt16),
    protocol LowCardinality(Nullable(String)),
    window_start DateTime64(3, 'UTC'),
    window_end DateTime64(3, 'UTC'),
    first_seen DateTime64(3, 'UTC'),
    last_seen DateTime64(3, 'UTC'),
    explanation String,
    alert_json String CODEC(ZSTD(3)),
    persisted_at DateTime64(3, 'UTC') DEFAULT now64(3),
    ingest_day Date DEFAULT toDate(persisted_at)
) ENGINE = ReplacingMergeTree(persisted_at)
PARTITION BY ingest_day
ORDER BY (incident_id, update_seq, update_id);

CREATE TABLE IF NOT EXISTS sih.incidents_latest
(
    incident_id UUID,
    update_seq UInt32,
    update_id UUID,
    status LowCardinality(String),
    ts DateTime64(6, 'UTC'),
    threat_class LowCardinality(String),
    subtype LowCardinality(String),
    severity LowCardinality(String),
    confidence Nullable(Float64),
    confidence_kind LowCardinality(String),
    calibration_status LowCardinality(String),
    model_version Nullable(String),
    detection_method LowCardinality(String),
    entity_type LowCardinality(String),
    entity_key String,
    src_ip Nullable(String),
    dst_ip Nullable(String),
    dst_port Nullable(UInt16),
    sensor_id LowCardinality(String),
    first_seen DateTime64(3, 'UTC'),
    last_seen DateTime64(3, 'UTC'),
    explanation String,
    alert_json String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree(update_seq)
ORDER BY incident_id;

CREATE MATERIALIZED VIEW IF NOT EXISTS sih.incidents_latest_mv TO sih.incidents_latest AS
SELECT incident_id, update_seq, update_id, status, ts, threat_class, subtype, severity, confidence, confidence_kind,
       calibration_status, model_version, detection_method, entity_type, entity_key, src_ip, dst_ip, dst_port, sensor_id,
       first_seen, last_seen, explanation, alert_json
FROM sih.alert_updates;

CREATE TABLE IF NOT EXISTS sih.invalid_events
(
    invalid_id UUID,
    detected_at DateTime64(6, 'UTC'),
    stage LowCardinality(String),
    reason_code LowCardinality(String),
    detail String,
    sensor_id Nullable(String),
    sensor_boot_id Nullable(String),
    sequence Nullable(UInt64),
    raw_sha256 Nullable(String),
    raw_size_bytes UInt32,
    raw_excerpt Nullable(String) CODEC(ZSTD(3)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    ingest_day Date DEFAULT toDate(ingested_at)
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY ingest_day
ORDER BY invalid_id;

CREATE TABLE IF NOT EXISTS sih.sensor_health
(
    sensor_id LowCardinality(String),
    sensor_boot_id String,
    health_seq UInt64,
    emitted_at DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC'),
    sender_state LowCardinality(String),
    last_sequence_sent Nullable(UInt64),
    records_read_total UInt64,
    records_invalid_local_total UInt64,
    records_rejected_oversize_total UInt64,
    spool_bytes UInt64,
    record_json String CODEC(ZSTD(3)),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    ingest_day Date DEFAULT toDate(ingested_at)
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY ingest_day
ORDER BY (sensor_id, sensor_boot_id, health_seq);

CREATE TABLE IF NOT EXISTS sih.consumer_quarantine
(
    consumer LowCardinality(String),
    topic LowCardinality(String),
    partition UInt32,
    offset UInt64,
    reason String,
    payload String CODEC(ZSTD(3)),
    quarantined_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(quarantined_at)
ORDER BY (consumer, topic, partition, offset);

CREATE TABLE IF NOT EXISTS sih.archive_manifest
(
    table_name LowCardinality(String),
    partition_id String,
    object_key String,
    rows UInt64,
    sha256 String,
    min_ingested DateTime64(3, 'UTC'),
    max_ingested DateTime64(3, 'UTC'),
    status LowCardinality(String),  -- exported | verified | deleted_hot
    exported_at DateTime64(3, 'UTC'),
    verified_at Nullable(DateTime64(3, 'UTC')),
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (table_name, partition_id);

INSERT INTO sih.schema_migrations (version) SELECT 1 WHERE (SELECT count() FROM sih.schema_migrations WHERE version = 1) = 0;
