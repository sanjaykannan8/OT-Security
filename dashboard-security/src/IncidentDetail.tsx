import { useEffect, useState } from "react";
import { api, HistoryUnavailable } from "./api";
import { confidenceLabel, fmtTime } from "./Dashboard";
import type { IncidentDetail } from "./types";

function KV({ title, data }: { title: string; data: Record<string, unknown> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <div>
      <h4>{title}</h4>
      <table className="compact">
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k}>
              <td className="mono">{k}</td>
              <td>{v === null ? <span className="muted">unavailable</span> : typeof v === "number" ? Number(v.toFixed(4)) : String(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function IncidentDetailPanel({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const [d, setD] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setD(null);
    setError(null);
    api
      .incident(incidentId)
      .then(setD)
      .catch((e) => setError(e instanceof HistoryUnavailable ? "History store unavailable; details will load when it recovers." : "Could not load incident."));
  }, [incidentId]);

  return (
    <aside className="drawer" aria-label="incident detail">
      <button className="close" onClick={onClose}>
        Close
      </button>
      {error && <p className="error">{error}</p>}
      {!d && !error && <p className="muted">Loading…</p>}
      {d && (
        <div>
          <h2>
            <span className={`sev sev-${d.incident.severity}`}>{d.incident.severity}</span> {d.incident.threat_class} / {d.incident.subtype}
          </h2>
          <p>{d.incident.explanation}</p>
          <table className="compact">
            <tbody>
              <tr><td>Entity</td><td className="mono">{d.incident.entity.type}: {d.incident.entity.key}</td></tr>
              <tr><td>Source → destination</td><td className="mono">{d.incident.src_ip ?? "many / n/a"}:{d.incident.src_port ?? "-"} → {d.incident.dst_ip ?? "many / n/a"}:{d.incident.dst_port ?? "-"} ({d.incident.protocol ?? "n/a"})</td></tr>
              <tr><td>Confidence</td><td>{confidenceLabel(d.incident)}</td></tr>
              <tr><td>Method / detector</td><td>{d.incident.detection_method} / {d.incident.detector_version}</td></tr>
              <tr><td>Model</td><td>{d.incident.model_version ?? "none (rules/statistics)"} — eligible: {String(d.incident.evidence.model_eligibility.eligible)}{d.incident.evidence.model_eligibility.reason ? ` (${d.incident.evidence.model_eligibility.reason})` : ""}</td></tr>
              <tr><td>Feature schema</td><td>{d.incident.feature_schema_version}</td></tr>
              <tr><td>Window</td><td>{fmtTime(d.incident.window_start)} – {fmtTime(d.incident.window_end)}</td></tr>
              <tr><td>First / last seen</td><td>{fmtTime(d.incident.first_seen)} / {fmtTime(d.incident.last_seen)}</td></tr>
              <tr><td>Capture time of evidence</td><td>{fmtTime(d.incident.event_time)}{d.incident.replay_run_id ? ` (replay ${d.incident.replay_run_id})` : ""}</td></tr>
              <tr><td>Coverage</td><td>{d.incident.evidence.visibility.observation_coverage}</td></tr>
              <tr><td>Unavailable features</td><td>{d.incident.evidence.visibility.unavailable_features.join(", ") || "none"}</td></tr>
              <tr><td>Capped (lower-bound) features</td><td>{d.incident.evidence.visibility.capped_features.join(", ") || "none"}</td></tr>
            </tbody>
          </table>
          <KV title="Observed" data={d.incident.evidence.observed} />
          <KV title="Thresholds" data={d.incident.evidence.thresholds} />
          <KV title="Baseline" data={d.incident.evidence.baseline} />
          {d.incident.top_features.length > 0 && (
            <div>
              <h4>Top features</h4>
              <table className="compact">
                <thead>
                  <tr><th>Feature</th><th>Value</th><th>Contribution</th></tr>
                </thead>
                <tbody>
                  {d.incident.top_features.map((f) => (
                    <tr key={f.name}>
                      <td className="mono">{f.name}</td>
                      <td>{f.value === null ? "unavailable" : `${Number(f.value.toFixed(4))} ${f.unit ?? ""}`}</td>
                      <td>{f.contribution === null ? "rule" : f.contribution.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <h4>Timeline</h4>
          <ol className="timeline">
            {d.updates.map((u) => (
              <li key={u.update_id}>
                {fmtTime(u.timestamp)} — #{u.update_seq} {u.status} ({u.severity}), evidence {u.evidence.evidence_count}
              </li>
            ))}
          </ol>
          <h4>Related raw events ({d.related_events.length}{d.incident.evidence.raw_event_ids_truncated ? ", truncated" : ""})</h4>
          {d.related_events.map((e, i) => (
            <pre key={i} className="raw">{JSON.stringify(e, null, 2)}</pre>
          ))}
        </div>
      )}
    </aside>
  );
}
