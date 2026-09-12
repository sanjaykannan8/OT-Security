import { ArrowRight, ClockCountdown, DotsThree, ShieldWarning, Siren, Sliders } from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import { type BarPoint, BarChart, HBars } from "./Charts";
import { fmtCount, fmtLatency, humanize } from "./format";
import type { Latency, Stats } from "./types";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

/** Open (unresolved) and total counts per severity, derived once per stats payload. */
function tally(stats: Stats) {
  const open = new Map<string, number>();
  const total = new Map<string, number>();
  for (const s of stats.severity) {
    if (!s.resolved) open.set(s.severity, (open.get(s.severity) ?? 0) + s.n);
    total.set(s.severity, (total.get(s.severity) ?? 0) + s.n);
  }
  const openAll = [...open.values()].reduce((a, b) => a + b, 0);
  const totalAll = [...total.values()].reduce((a, b) => a + b, 0);
  return { open, total, openAll, totalAll };
}

function StatCard({
  hero,
  icon,
  title,
  subtitle,
  value,
  pill,
  footer,
  onOpen,
}: {
  hero?: boolean;
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  value: string;
  pill?: string;
  footer: string;
  onOpen: () => void;
}) {
  return (
    <article className={`card stat${hero ? " hero" : ""}`}>
      <div className="stat-top">
        <span className="icon-tile">{icon}</span>
        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
        <span className="spacer" />
        <DotsThree size={20} weight="bold" style={{ opacity: 0.5 }} />
      </div>
      <div className="stat-value">
        <span className="n">{value}</span>
        {pill && <span className="pill">{pill}</span>}
      </div>
      <div className="stat-foot">
        {footer}
        <button className="icon-btn sm" onClick={onOpen} aria-label={`${title}: open details`}>
          <ArrowRight size={15} weight="bold" />
        </button>
      </div>
    </article>
  );
}

export function HeroRow({ stats, onOpen }: { stats: Stats; onOpen: (severity: string) => void }) {
  const { open, openAll, totalAll } = tally(stats);
  const urgent = (open.get("critical") ?? 0) + (open.get("high") ?? 0);
  const share = openAll > 0 ? Math.round((urgent / openAll) * 100) : 0;
  const lat = stats.detection_latency;

  return (
    <div className="row-3">
      <StatCard
        hero
        icon={<ShieldWarning size={20} weight="fill" />}
        title="Open incidents"
        subtitle={`Unresolved, last ${stats.window_minutes} min`}
        value={fmtCount(openAll)}
        pill={`${fmtCount(totalAll - openAll)} resolved`}
        footer="Review the queue"
        onOpen={() => onOpen("")}
      />
      <StatCard
        icon={<Siren size={20} weight="fill" className="sev-critical" />}
        title="Critical and high"
        subtitle="Needs an analyst first"
        value={fmtCount(urgent)}
        pill={`${share}% of open`}
        footer="Triage by severity"
        onOpen={() => onOpen("critical")}
      />
      <StatCard
        icon={<ClockCountdown size={20} weight="fill" />}
        title="Detection latency"
        subtitle="p95, evidence to stored alert"
        value={lat.samples > 0 ? fmtLatency(lat.p95_ms, lat.p95_s) : "n/a"}
        pill={lat.samples > 0 ? `${fmtCount(lat.over_5s ?? 0)} over 5 s` : undefined}
        footer={lat.samples > 0 ? `${fmtCount(lat.samples)} samples` : "No samples yet"}
        onOpen={() => onOpen("")}
      />
    </div>
  );
}

export function SeverityBreakdown({ stats, onPick }: { stats: Stats; onPick: (severity: string) => void }) {
  const { open, total, totalAll } = tally(stats);
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Severity breakdown</h2>
          <p>Open against everything seen in the window</p>
        </div>
        <div className="controls">
          <button className="btn btn-accent" onClick={() => onPick("critical")}>
            <Sliders size={15} weight="bold" />
            Critical only
          </button>
        </div>
      </div>
      <div className="sev-grid">
        {SEV_ORDER.map((s) => (
          <button key={s} className={`sev-tile sev-${s}`} onClick={() => onPick(s)}>
            <header>
              <i className="dot" />
              {s}
            </header>
            <span className="n" style={{ color: "var(--text)" }}>
              {fmtCount(open.get(s) ?? 0)}
            </span>
            <span className="of">of {fmtCount(total.get(s) ?? 0)} seen</span>
            <div className="open">{totalAll > 0 ? `${Math.round(((total.get(s) ?? 0) / totalAll) * 100)}% of volume` : "-"}</div>
          </button>
        ))}
      </div>
    </section>
  );
}

export function AlertRate({ stats }: { stats: Stats }) {
  const [grain, setGrain] = useState<"minute" | "hour">("minute");

  const points: BarPoint[] = useMemo(() => {
    const raw = stats.alert_rate_per_minute;
    if (grain === "minute") {
      return raw.slice(-30).map((p) => ({
        label: new Date(p.minute).toISOString().slice(11, 16),
        title: new Date(p.minute).toISOString().replace("T", " ").slice(0, 16) + "Z",
        n: p.n,
      }));
    }
    const buckets = new Map<string, number>();
    for (const p of raw) {
      const key = new Date(p.minute).toISOString().slice(0, 13);
      buckets.set(key, (buckets.get(key) ?? 0) + p.n);
    }
    return [...buckets.entries()].map(([k, n]) => ({ label: `${k.slice(11)}:00`, title: `${k.replace("T", " ")}:00Z`, n }));
  }, [stats.alert_rate_per_minute, grain]);

  const total = stats.alert_rate_per_minute.reduce((a, p) => a + p.n, 0);

  return (
    <section className="card fill">
      <div className="card-head">
        <div>
          <p className="muted small" style={{ margin: 0 }}>
            Alert updates
          </p>
          <p className="chart-value">{fmtCount(total)}</p>
        </div>
        <div className="controls">
          <div className="seg" role="group" aria-label="chart grain">
            <button aria-pressed={grain === "minute"} onClick={() => setGrain("minute")}>
              <i className="dot" />
              Per minute
            </button>
            <button aria-pressed={grain === "hour"} onClick={() => setGrain("hour")}>
              <i className="dot" />
              Per hour
            </button>
          </div>
        </div>
      </div>
      <BarChart points={points} unit="updates" />
    </section>
  );
}

export function ThreatClasses({ stats }: { stats: Stats }) {
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Threat classes</h2>
          <p>Alert updates by detector class</p>
        </div>
      </div>
      <HBars items={stats.threat_classes.map((t) => ({ label: humanize(t.threat_class), n: t.n }))} />
    </section>
  );
}

export function ConfidenceDistribution({ stats }: { stats: Stats }) {
  const items = useMemo(() => {
    const conf = new Map<string, number>();
    for (const c of stats.confidence) {
      const key =
        c.bucket < 0
          ? `${humanize(c.confidence_kind)} - unavailable`
          : `${humanize(c.confidence_kind)} ${c.bucket.toFixed(1)} (${humanize(c.calibration_status)})`;
      conf.set(key, (conf.get(key) ?? 0) + c.n);
    }
    return [...conf.entries()].map(([label, n]) => ({ label, n }));
  }, [stats.confidence]);

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Confidence distribution</h2>
          <p>Heuristic scores are not calibrated probabilities</p>
        </div>
      </div>
      <HBars items={items} />
      <p className="muted small" style={{ marginBottom: 0 }}>
        No accuracy figure is shown: live traffic carries no ground truth.
      </p>
    </section>
  );
}

export function LatencyCard({ title, l, note }: { title: string; l: Latency | undefined; note: string }) {
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          <p>{note}</p>
        </div>
      </div>
      {!l || l.samples === 0 ? (
        <p className="muted small">No samples yet.</p>
      ) : (
        <dl className="kv">
          <dt>p50 / p90</dt>
          <dd>
            {fmtLatency(l.p50_ms, l.p50_s)} / {fmtLatency(l.p90_ms, l.p90_s)}
          </dd>
          <dt>p95 / p99</dt>
          <dd>
            {fmtLatency(l.p95_ms, l.p95_s)} / {fmtLatency(l.p99_ms, l.p99_s)}
          </dd>
          <dt>Maximum</dt>
          <dd>{fmtLatency(l.max_ms, l.max_s)}</dd>
          <dt>Over 5 s</dt>
          <dd>
            {fmtCount(l.over_5s ?? 0)} of {fmtCount(l.samples)}
          </dd>
        </dl>
      )}
      <p className="muted small" style={{ marginBottom: 0, marginTop: 12 }}>
        {l?.definition}
      </p>
    </section>
  );
}
