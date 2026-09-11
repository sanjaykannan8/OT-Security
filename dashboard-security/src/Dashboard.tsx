import { type ChangeEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, type Filters, HistoryUnavailable, type Me } from "./api";
import { IncidentDetailPanel } from "./IncidentDetail";
import { StatsPanel } from "./StatsPanel";
import { type Alert, type IncidentRow, rowFromAlert, type Stats } from "./types";

type StreamState = "connecting" | "live" | "reconnecting" | "resyncing";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const CLASSES = ["", "ddos", "scan", "beaconing", "dga", "dns_tunnel", "encrypted_malware_like", "exfiltration"];
const STATUSES = ["", "new", "escalated", "updated", "resolved"];

export function fmtTime(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().replace("T", " ").slice(0, 23);
}

export function confidenceLabel(r: { confidence: number | null; confidence_kind: string; calibration_status: string }): string {
  if (r.confidence === null || r.confidence_kind === "unavailable") return "unavailable";
  const kind = r.confidence_kind === "calibrated_probability" ? "prob." : "score";
  const cal = r.calibration_status === "calibrated" ? "" : ` (${r.calibration_status.replace("_", " ")})`;
  return `${r.confidence.toFixed(2)} ${kind}${cal}`;
}

export function Dashboard({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [filters, setFilters] = useState<Filters>({ severity: "", threat_class: "", status: "", q: "", since_minutes: 1440 });
  const [rows, setRows] = useState<IncidentRow[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [historyStale, setHistoryStale] = useState(false);
  const [stream, setStream] = useState<StreamState>("connecting");
  const [liveCount, setLiveCount] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  const loadHistory = useCallback(async () => {
    try {
      const [inc, st] = await Promise.all([api.incidents(filtersRef.current), api.stats(60)]);
      setRows(inc.items);
      setStats(st);
      setHistoryStale(false);
    } catch (e) {
      if (e instanceof HistoryUnavailable) setHistoryStale(true);
    }
  }, []);

  useEffect(() => {
    void loadHistory();
    const t = window.setInterval(() => void loadHistory(), 15000);
    return () => window.clearInterval(t);
  }, [loadHistory, filters]);

  useEffect(() => {
    const es = new EventSource("/api/stream", { withCredentials: true });
    es.onopen = () => setStream("live");
    es.onerror = () => setStream("reconnecting");
    es.addEventListener("resync", () => {
      setStream("resyncing");
      void loadHistory().then(() => setStream("live"));
    });
    es.addEventListener("alert", (ev) => {
      let a: Alert;
      try {
        a = JSON.parse((ev as MessageEvent<string>).data) as Alert;
      } catch {
        return;
      }
      setLiveCount((n) => n + 1);
      setRows((prev) => {
        const i = prev.findIndex((r) => r.incident_id === a.incident_id);
        if (i >= 0 && prev[i].update_seq >= a.update_seq) return prev;
        const next = i >= 0 ? prev.filter((_, j) => j !== i) : prev;
        return [rowFromAlert(a), ...next].slice(0, 500);
      });
    });
    return () => es.close();
  }, [loadHistory]);

  const visible = useMemo(
    () =>
      rows.filter(
        (r) =>
          (!filters.severity || r.severity === filters.severity) &&
          (!filters.threat_class || r.threat_class === filters.threat_class) &&
          (!filters.status || r.status === filters.status) &&
          (!filters.q || `${r.entity_key} ${r.explanation}`.toLowerCase().includes(filters.q.toLowerCase())),
      ),
    [rows, filters],
  );

  const set = (k: keyof Filters) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const value = k === "since_minutes" ? Number(e.target.value) : e.target.value;
    setFilters((f) => ({ ...f, [k]: value }) as Filters);
  };

  return (
    <div className="app">
      <header>
        <strong>SIH SOC</strong>
        <span className={`badge stream-${stream}`}>live stream: {stream}</span>
        {historyStale && <span className="badge warn">history store unavailable: showing live data only</span>}
        <span className="spacer" />
        <span className="muted">
          {me.user} ({me.role})
        </span>
        <button onClick={onLogout}>Sign out</button>
      </header>
      <div className="banner">{me.disclaimer}</div>
      <StatsPanel stats={stats} liveCount={liveCount} />
      <section className="card">
        <div className="filters">
          <select value={filters.severity} onChange={set("severity")} aria-label="severity">
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s || "any severity"}
              </option>
            ))}
          </select>
          <select value={filters.threat_class} onChange={set("threat_class")} aria-label="threat class">
            {CLASSES.map((s) => (
              <option key={s} value={s}>
                {s || "any class"}
              </option>
            ))}
          </select>
          <select value={filters.status} onChange={set("status")} aria-label="status">
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s || "any status"}
              </option>
            ))}
          </select>
          <select value={filters.since_minutes} onChange={set("since_minutes")} aria-label="time range">
            <option value={60}>last hour</option>
            <option value={1440}>last 24 h</option>
            <option value={10080}>last 7 days</option>
          </select>
          <input placeholder="search entity or explanation" value={filters.q} onChange={set("q")} maxLength={128} />
        </div>
        <table>
          <thead>
            <tr>
              <th>Last update</th>
              <th>Severity</th>
              <th>Class / subtype</th>
              <th>Entity</th>
              <th>Confidence</th>
              <th>Method</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r) => (
              <tr key={r.incident_id} onClick={() => setSelected(r.incident_id)} className={selected === r.incident_id ? "sel" : ""}>
                <td>{fmtTime(r.ts)}</td>
                <td>
                  <span className={`sev sev-${r.severity}`}>{r.severity}</span>
                </td>
                <td>
                  {r.threat_class} / {r.subtype}
                </td>
                <td className="mono">{r.entity_key}</td>
                <td>{confidenceLabel(r)}</td>
                <td>{r.detection_method}</td>
                <td>{r.status}</td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  No incidents match. Alerts appear here as they stream in.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
      {selected && <IncidentDetailPanel incidentId={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
