export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface TopFeature {
  name: string;
  value: number | null;
  contribution: number | null;
  unit: string | null;
}

export interface Alert {
  alert_id: string;
  incident_id: string;
  update_id: string;
  update_seq: number;
  status: string;
  timestamp: string;
  event_time: string;
  observation_time: string;
  evidence_received_at: string;
  api_received_at?: string;
  sensor_id: string;
  replay_run_id: string | null;
  flow_id: string | null;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  entity: { type: string; key: string };
  threat_class: string;
  subtype: string;
  severity: Severity;
  confidence: number | null;
  confidence_kind: string;
  calibration_status: string;
  model_version: string | null;
  detector_version: string;
  feature_schema_version: string;
  detection_method: string;
  evidence: {
    observed: Record<string, number | string | boolean | null>;
    thresholds: Record<string, number | null>;
    baseline: Record<string, number | null>;
    visibility: { observation_coverage: string; unavailable_features: string[]; capped_features: string[] };
    model_eligibility: { eligible: boolean; reason: string | null };
    raw_event_ids: string[];
    raw_event_ids_truncated: boolean;
    evidence_count: number;
  };
  top_features: TopFeature[];
  explanation: string;
  window_start: string;
  window_end: string;
  first_seen: string;
  last_seen: string;
}

export interface IncidentRow {
  incident_id: string;
  update_seq: number;
  status: string;
  ts: string;
  threat_class: string;
  subtype: string;
  severity: Severity;
  confidence: number | null;
  confidence_kind: string;
  calibration_status: string;
  model_version: string | null;
  detection_method: string;
  entity_type: string;
  entity_key: string;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  sensor_id: string;
  first_seen: string;
  last_seen: string;
  explanation: string;
}

export interface Latency {
  definition: string;
  samples: number;
  p50_ms?: number | null;
  p90_ms?: number | null;
  p95_ms?: number | null;
  p99_ms?: number | null;
  max_ms?: number | null;
  over_5s?: number;
  p50_s?: number;
  p90_s?: number;
  p95_s?: number;
  p99_s?: number;
  max_s?: number;
}

export interface Stats {
  window_minutes: number;
  severity: { severity: Severity; resolved: number; n: number }[];
  threat_classes: { threat_class: string; n: number }[];
  alert_rate_per_minute: { minute: string; n: number }[];
  confidence: { confidence_kind: string; calibration_status: string; bucket: number; n: number }[];
  detection_latency: Latency;
  api_visible_latency: Latency;
}

export interface IncidentDetail {
  incident: Alert;
  updates: Alert[];
  related_events: Record<string, unknown>[];
}

export function rowFromAlert(a: Alert): IncidentRow {
  return {
    incident_id: a.incident_id,
    update_seq: a.update_seq,
    status: a.status,
    ts: a.timestamp,
    threat_class: a.threat_class,
    subtype: a.subtype,
    severity: a.severity,
    confidence: a.confidence,
    confidence_kind: a.confidence_kind,
    calibration_status: a.calibration_status,
    model_version: a.model_version,
    detection_method: a.detection_method,
    entity_type: a.entity.type,
    entity_key: a.entity.key,
    src_ip: a.src_ip,
    dst_ip: a.dst_ip,
    dst_port: a.dst_port,
    sensor_id: a.sensor_id,
    first_seen: a.first_seen,
    last_seen: a.last_seen,
    explanation: a.explanation,
  };
}
