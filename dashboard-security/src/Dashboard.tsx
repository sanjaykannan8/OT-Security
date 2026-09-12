import { ArrowsClockwise } from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, type Filters, HistoryUnavailable, type Me } from "./api";
import { entityIcon } from "./brand";
import { IncidentDetailPanel } from "./IncidentDetail";
import { FilterSelect } from "./controls";
import { IncidentTable, SeverityBadge } from "./IncidentTable";
import { fmtAge, fmtCount, humanize } from "./format";
import { Sidebar, type View } from "./Sidebar";
import {
  AlertRate,
  ConfidenceDistribution,
  HeroRow,
  LatencyCard,
  SeverityBreakdown,
  ThreatClasses,
} from "./StatsPanel";
import { TopBar, type StreamState } from "./TopBar";
import { type Alert, type IncidentRow, rowFromAlert, type Stats } from "./types";

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const MAX_ROWS = 500;

const RANGES = [
  { value: "60", label: "Last hour" },
  { value: "1440", label: "Last 24 h" },
  { value: "10080", label: "Last 7 days" },
];

const SUBTITLES: Record<View, string> = {
  overview: "Passive detection across the monitored OT segment.",
  incidents: "Every alert update the detector has published in this window.",
  entities: "Monitored assets ranked by the worst severity seen against them.",
  detections: "How detections were produced, and how quickly.",
};

export function Dashboard({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [view, setView] = useState<View>("overview");
  const [filters, setFilters] = useState<Filters>({
    severity: "",
    threat_class: "",
    status: "",
    q: "",
    since_minutes: 1440,
  });
  const [rows, setRows] = useState<IncidentRow[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [historyStale, setHistoryStale] = useState(false);
  const [stream, setStream] = useState<StreamState>("connecting");
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState<IncidentRow[]>([]);

  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const searchRef = useRef<HTMLInputElement | null>(null);
  /** True while the pointer rests on the table: live updates must not reorder rows under it. */
  const holdRef = useRef(false);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  const loadHistory = useCallback(async () => {
    try {
      const [inc, st] = await Promise.all([api.incidents(filtersRef.current), api.stats(60)]);
      setRows(inc.items);
      setStats(st);
      setPending([]);
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

  /** Merge a batch of updates into the table, newest first, keeping one row per incident. */
  const merge = useCallback((incoming: IncidentRow[]) => {
    if (incoming.length === 0) return;
    setRows((prev) => {
      const next = [...prev];
      for (const r of incoming) {
        const i = next.findIndex((x) => x.incident_id === r.incident_id);
        if (i >= 0) {
          if (next[i].update_seq >= r.update_seq) continue;
          next.splice(i, 1);
        }
        next.unshift(r);
      }
      return next.slice(0, MAX_ROWS);
    });
  }, []);

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
      const row = rowFromAlert(a);
      if (holdRef.current || selectedRef.current !== null) setPending((p) => [row, ...p].slice(0, MAX_ROWS));
      else merge([row]);
    });
    return () => es.close();
  }, [loadHistory, merge]);

  const flush = useCallback(() => {
    setPending((p) => {
      merge([...p].reverse());
      return [];
    });
  }, [merge]);

  /* Release the hold as soon as the analyst is done reading, so the table catches up. */
  useEffect(() => {
    if (selected === null && !holdRef.current && pending.length > 0) {
      const t = window.setTimeout(flush, 4000);
      return () => window.clearTimeout(t);
    }
  }, [selected, pending.length, flush]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const visible = useMemo(
    () =>
      rows.filter(
        (r) =>
          (!filters.severity || r.severity === filters.severity) &&
          (!filters.threat_class || r.threat_class === filters.threat_class) &&
          (!filters.status || r.status === filters.status) &&
          (!filters.q || `${r.entity_key} ${r.entity_type} ${r.explanation}`.toLowerCase().includes(filters.q.toLowerCase())),
      ),
    [rows, filters],
  );

  const entities = useMemo(() => {
    const by = new Map<string, { key: string; type: string; n: number; worst: string; last: string }>();
    for (const r of visible) {
      const e = by.get(r.entity_key);
      if (!e) by.set(r.entity_key, { key: r.entity_key, type: r.entity_type, n: 1, worst: r.severity, last: r.ts });
      else {
        e.n += 1;
        if ((SEV_RANK[r.severity] ?? 0) > (SEV_RANK[e.worst] ?? 0)) e.worst = r.severity;
        if (r.ts > e.last) e.last = r.ts;
      }
    }
    return [...by.values()].sort((a, b) => (SEV_RANK[b.worst] ?? 0) - (SEV_RANK[a.worst] ?? 0) || b.n - a.n);
  }, [visible]);

  const onFilter = useCallback((patch: Partial<Filters>) => setFilters((f) => ({ ...f, ...patch })), []);

  const jumpTo = useCallback((severity: string) => {
    setFilters((f) => ({ ...f, severity }));
    setView("incidents");
  }, []);

  const exportEvidence = useCallback(() => {
    const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), filters, incidents: visible }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-incidents-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filters, visible]);

  const table = (
    <div onMouseEnter={() => (holdRef.current = true)} onMouseLeave={() => (holdRef.current = false)}>
      <IncidentTable
        rows={visible}
        filters={filters}
        onFilter={onFilter}
        selected={selected}
        onSelect={setSelected}
        pending={pending.length}
        onFlush={flush}
      />
    </div>
  );

  return (
    <div className="shell">
      <Sidebar
        view={view}
        onView={setView}
        counts={{ incidents: visible.length, entities: entities.length }}
        me={me}
        onLogout={onLogout}
        query={filters.q}
        onQuery={(q) => onFilter({ q })}
        searchRef={searchRef}
      />

      <div className="main">
        <TopBar
          view={view}
          stream={stream}
          historyStale={historyStale}
          onRefresh={() => void loadHistory()}
          onExport={exportEvidence}
        />

        <main className="content">
          <div className="page-head">
            <div>
              <h1>{view === "overview" ? "Overview" : view[0].toUpperCase() + view.slice(1)}</h1>
              <p>{SUBTITLES[view]}</p>
            </div>
            <div className="controls">
              <FilterSelect
                label="time range"
                value={String(filters.since_minutes)}
                onChange={(v) => onFilter({ since_minutes: Number(v) })}
                options={RANGES}
                width={152}
              />
              <button className="btn btn-ghost" onClick={() => void loadHistory()}>
                <ArrowsClockwise size={15} weight="bold" />
                Refresh
              </button>
            </div>
          </div>

          {!stats && (
            <section className="card muted">
              Statistics are unavailable - the history store is not reachable yet. Live updates still arrive below.
            </section>
          )}

          {view === "overview" && stats && (
            <>
              <HeroRow stats={stats} onOpen={jumpTo} />
              <div className="row-split">
                <SeverityBreakdown stats={stats} onPick={jumpTo} />
                <AlertRate stats={stats} />
              </div>
            </>
          )}

          {(view === "overview" || view === "incidents") && table}

          {view === "entities" && (
            <section className="card solid">
              <div className="card-head">
                <div>
                  <h2>Monitored entities</h2>
                  <p>{entities.length} with at least one alert in this window</p>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Entity</th>
                      <th>Worst severity</th>
                      <th>Alert updates</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entities.map((e) => {
                      const Glyph = entityIcon(e.type);
                      return (
                        <tr
                          key={e.key}
                          tabIndex={0}
                          onClick={() => {
                            onFilter({ q: e.key });
                            setView("incidents");
                          }}
                          onKeyDown={(ev) => {
                            if (ev.key === "Enter" || ev.key === " ") {
                              ev.preventDefault();
                              onFilter({ q: e.key });
                              setView("incidents");
                            }
                          }}
                        >
                          <td>
                            <div className="entity">
                              <span className="icon-tile">
                                <Glyph size={15} />
                              </span>
                              <div>
                                <div className="key" title={e.key}>{e.key}</div>
                                <div className="kind">{humanize(e.type)}</div>
                              </div>
                            </div>
                          </td>
                          <td className="tight">
                            <SeverityBadge severity={e.worst} />
                          </td>
                          <td className="nums">{fmtCount(e.n)}</td>
                          <td className="when">{fmtAge(e.last)}</td>
                        </tr>
                      );
                    })}
                    {entities.length === 0 && (
                      <tr>
                        <td colSpan={4}>
                          <div className="empty">No entities have alerted in this window.</div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {view === "detections" && stats && (
            <>
              <div className="row-2">
                <ThreatClasses stats={stats} />
                <ConfidenceDistribution stats={stats} />
              </div>
              <div className="row-2">
                <LatencyCard
                  title="Detection latency"
                  l={stats.detection_latency}
                  note="Measured from stored timestamps"
                />
                <LatencyCard
                  title="API-visible latency"
                  l={stats.api_visible_latency}
                  note="Measured inside this API process"
                />
              </div>
            </>
          )}
        </main>
      </div>

      {selected && <IncidentDetailPanel incidentId={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
