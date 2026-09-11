import type { Latency, Stats } from "./types";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function Bars({ items }: { items: { label: string; n: number }[] }) {
  const max = Math.max(1, ...items.map((i) => i.n));
  const rowH = 18;
  return (
    <svg className="bars" viewBox={`0 0 300 ${Math.max(rowH, items.length * rowH)}`} role="img">
      {items.map((it, i) => (
        <g key={it.label} transform={`translate(0 ${i * rowH})`}>
          <text x={0} y={13} className="bar-label">
            {it.label}
          </text>
          <rect x={150} y={3} height={12} width={(it.n / max) * 120} className="bar" />
          <text x={276} y={13} className="bar-value">
            {it.n}
          </text>
        </g>
      ))}
    </svg>
  );
}

function Sparkline({ points }: { points: { minute: string; n: number }[] }) {
  if (points.length === 0) return <p className="muted">No alert updates in the window.</p>;
  const max = Math.max(1, ...points.map((p) => p.n));
  const w = 300;
  const h = 60;
  const step = points.length > 1 ? w / (points.length - 1) : w;
  const d = points.map((p, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)} ${(h - (p.n / max) * (h - 4)).toFixed(1)}`).join(" ");
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="alert updates per minute">
      <path d={d} className="spark-line" />
    </svg>
  );
}

function LatencyTable({ title, l, unit }: { title: string; l: Latency | undefined; unit: "ms" | "s" }) {
  if (!l || l.samples === 0) {
    return (
      <div>
        <h3>{title}</h3>
        <p className="muted">No samples yet.</p>
      </div>
    );
  }
  const v = (ms?: number | null, s?: number) => {
    const x = unit === "ms" ? (ms ?? null) : s !== undefined ? s * 1000 : null;
    return x === null || x === undefined ? "n/a" : `${(x / 1000).toFixed(2)} s`;
  };
  return (
    <div>
      <h3>{title}</h3>
      <table className="compact">
        <tbody>
          <tr>
            <td>p50 / p90</td>
            <td>
              {v(l.p50_ms, l.p50_s)} / {v(l.p90_ms, l.p90_s)}
            </td>
          </tr>
          <tr>
            <td>p95 / p99</td>
            <td>
              {v(l.p95_ms, l.p95_s)} / {v(l.p99_ms, l.p99_s)}
            </td>
          </tr>
          <tr>
            <td>max, over 5 s</td>
            <td>
              {v(l.max_ms, l.max_s)}, {l.over_5s ?? 0} of {l.samples}
            </td>
          </tr>
        </tbody>
      </table>
      <p className="muted small">{l.definition}</p>
    </div>
  );
}

export function StatsPanel({ stats, liveCount }: { stats: Stats | null; liveCount: number }) {
  if (!stats) {
    return <section className="card muted">Statistics unavailable (history store not reachable yet). Live updates received: {liveCount}</section>;
  }
  const open = new Map<string, number>();
  for (const s of stats.severity) if (!s.resolved) open.set(s.severity, (open.get(s.severity) ?? 0) + s.n);
  const conf = new Map<string, number>();
  for (const c of stats.confidence) {
    const key = c.bucket < 0 ? `${c.confidence_kind}: unavailable` : `${c.confidence_kind} (${c.calibration_status}) ${c.bucket.toFixed(1)}`;
    conf.set(key, (conf.get(key) ?? 0) + c.n);
  }
  return (
    <section className="grid">
      <div className="card">
        <h3>Open incidents by severity (last {stats.window_minutes} min)</h3>
        <div className="sev-row">
          {SEV_ORDER.map((s) => (
            <div key={s} className={`sev-card sev-${s}`}>
              <div className="big">{open.get(s) ?? 0}</div>
              <div>{s}</div>
            </div>
          ))}
        </div>
        <p className="muted small">Live updates received this session: {liveCount}</p>
      </div>
      <div className="card">
        <h3>Alert updates per minute</h3>
        <Sparkline points={stats.alert_rate_per_minute} />
        <h3>Threat classes</h3>
        <Bars items={stats.threat_classes.map((t) => ({ label: t.threat_class, n: t.n }))} />
      </div>
      <div className="card">
        <h3>Confidence distribution</h3>
        <Bars items={[...conf.entries()].map(([label, n]) => ({ label, n }))} />
        <p className="muted small">Heuristic scores and simulation-only model outputs are not calibrated probabilities. No accuracy is shown because live traffic has no ground truth.</p>
      </div>
      <div className="card">
        <LatencyTable title="Detection latency (stored timestamps)" l={stats.detection_latency} unit="ms" />
        <LatencyTable title="API-visible latency (this API process)" l={stats.api_visible_latency} unit="s" />
      </div>
    </section>
  );
}
