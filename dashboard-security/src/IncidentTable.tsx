import { ArrowUp, DotsThree, Funnel, MagnifyingGlass, ShieldCheck } from "@phosphor-icons/react";
import type { ChangeEvent } from "react";
import type { Filters } from "./api";
import { entityIcon } from "./brand";
import { FilterSelect, type Option } from "./controls";
import { confidenceLabel, fmtAge, fmtTime, humanize } from "./format";
import type { IncidentRow } from "./types";

const cap = (s: string) => s.slice(0, 1).toUpperCase() + s.slice(1).replace(/_/g, " ");
const opts = (values: string[], any: string): Option[] =>
  values.map((v) => ({ value: v, label: v ? cap(v) : any }));

const SEVERITIES = opts(["", "critical", "high", "medium", "low", "info"], "Any severity");
const CLASSES = opts(
  ["", "ddos", "scan", "beaconing", "dga", "dns_tunnel", "encrypted_malware_like", "exfiltration"],
  "Any class",
);
const STATUSES = opts(["", "new", "escalated", "updated", "resolved"], "Any status");

/** Status is state, not severity, so it gets its own neutral-to-green scale. */
const STATUS_TONE: Record<string, string> = {
  new: "var(--accent)",
  escalated: "var(--sev-critical)",
  updated: "var(--sev-medium)",
  resolved: "var(--ok)",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`sev-badge sev-${severity}`}>
      <i className="dot" />
      {severity}
    </span>
  );
}

export function IncidentTable({
  rows,
  filters,
  onFilter,
  selected,
  onSelect,
  pending,
  onFlush,
  showFilters = true,
}: {
  rows: IncidentRow[];
  filters: Filters;
  onFilter: (patch: Partial<Filters>) => void;
  selected: string | null;
  onSelect: (id: string) => void;
  pending: number;
  onFlush: () => void;
  showFilters?: boolean;
}) {
  const set = (k: keyof Filters) => (e: ChangeEvent<HTMLInputElement>) =>
    onFilter({ [k]: e.target.value } as Partial<Filters>);

  return (
    <section className="card solid">
      <div className="card-head">
        <div>
          <h2>Incidents</h2>
          <p>
            {rows.length} shown{filters.q ? ` matching “${filters.q}”` : ""}
          </p>
        </div>
        {showFilters && (
          <div className="controls">
            <div className="field" style={{ width: 220 }}>
              <MagnifyingGlass size={15} weight="bold" />
              <input
                value={filters.q}
                onChange={set("q")}
                placeholder="Search entity or reason"
                aria-label="search incidents"
                maxLength={128}
              />
            </div>
            <FilterSelect
              label="severity"
              icon={<Funnel size={14} weight="bold" />}
              value={filters.severity}
              onChange={(severity) => onFilter({ severity })}
              options={SEVERITIES}
              width={162}
            />
            <FilterSelect
              label="threat class"
              value={filters.threat_class}
              onChange={(threat_class) => onFilter({ threat_class })}
              options={CLASSES}
              width={186}
            />
            <FilterSelect
              label="status"
              value={filters.status}
              onChange={(status) => onFilter({ status })}
              options={STATUSES}
              width={148}
            />
          </div>
        )}
      </div>

      {pending > 0 && (
        <button className="newer" onClick={onFlush}>
          <ArrowUp size={14} weight="bold" />
          {pending} newer {pending === 1 ? "update" : "updates"} - show them
        </button>
      )}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Entity</th>
              <th>Class</th>
              <th>Last update</th>
              <th>Confidence</th>
              <th>Method</th>
              <th>Status</th>
              <th aria-label="actions" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const Glyph = entityIcon(r.entity_type);
              return (
                <tr
                  key={r.incident_id}
                  tabIndex={0}
                  aria-selected={selected === r.incident_id}
                  onClick={() => onSelect(r.incident_id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelect(r.incident_id);
                    }
                  }}
                >
                  <td className="tight">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td>
                    <div className="entity">
                      <span className="icon-tile">
                        <Glyph size={15} />
                      </span>
                      <div>
                        <div className="key" title={r.entity_key}>{r.entity_key}</div>
                        <div className="kind">{humanize(r.entity_type)}</div>
                      </div>
                    </div>
                  </td>
                  <td className="klass">
                    {humanize(r.threat_class)} <span>/ {humanize(r.subtype)}</span>
                  </td>
                  <td className="when">
                    <span className="rel">{fmtAge(r.ts)}</span>
                    <div className="dim small" title={fmtTime(r.ts)}>
                      {fmtTime(r.ts).slice(11)}
                    </div>
                  </td>
                  <td className="nums">{confidenceLabel(r)}</td>
                  <td className="muted">{humanize(r.detection_method)}</td>
                  <td className="tight">
                    <span className="pill" style={{ color: STATUS_TONE[r.status] ?? "var(--text-2)" }}>
                      <i className="dot" />
                      {r.status}
                    </span>
                  </td>
                  <td className="tight">
                    <DotsThree size={18} weight="bold" className="dim" />
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <div className="empty">
                    <ShieldCheck size={28} weight="duotone" />
                    <div>No incidents match these filters.</div>
                    <div className="small dim">Alerts appear here as they stream in.</div>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
