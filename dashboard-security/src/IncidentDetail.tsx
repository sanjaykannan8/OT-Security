import { Dialog } from "@base-ui-components/react/dialog";
import { X } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { api, HistoryUnavailable } from "./api";
import { SeverityBadge } from "./IncidentTable";
import { confidenceLabel, fmtCount, fmtEvidence, fmtTime, humanize } from "./format";
import type { IncidentDetail } from "./types";

function KV({ title, data }: { title: string; data: Record<string, unknown> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <section>
      <h3>{title}</h3>
      <dl className="kv">
        {entries.map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <dt className="mono">{k}</dt>
            <dd className={v === null ? "dim" : undefined}>{fmtEvidence(k, v)}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export function IncidentDetailPanel({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const [d, setD] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    setD(null);
    setError(null);
    api
      .incident(incidentId)
      .then(setD)
      .catch((e) =>
        setError(
          e instanceof HistoryUnavailable
            ? "The history store is unavailable. Details will load when it recovers."
            : "Could not load this incident.",
        ),
      );
  }, [incidentId]);

  /*
   * Put focus inside the panel on open. Base UI's own `initialFocus` is skipped for
   * pointer-opened dialogs in 1.0.0-rc.0, and focus left outside would let Tab walk
   * straight back out of the modal, so place it explicitly on Close.
   */
  useEffect(() => {
    const t = window.setTimeout(() => closeRef.current?.focus(), 0);
    return () => window.clearTimeout(t);
  }, []);

  const inc = d?.incident;
  const maxContribution = Math.max(0.0001, ...(inc?.top_features ?? []).map((f) => Math.abs(f.contribution ?? 0)));

  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Backdrop className="scrim" />
        <Dialog.Popup className="drawer" aria-label="incident detail">
          <header className="drawer-head">
          {inc && <SeverityBadge severity={inc.severity} />}
          <div>
            <h2>{inc ? `${humanize(inc.threat_class)} / ${humanize(inc.subtype)}` : "Incident"}</h2>
            {inc && <div className="sub mono">{incidentId}</div>}
          </div>
          <span className="spacer" />
          <Dialog.Close className="icon-btn" aria-label="Close" ref={closeRef}>
            <X size={16} weight="bold" />
          </Dialog.Close>
        </header>

        <div className="drawer-body">
          {error && <p className="error">{error}</p>}
          {!d && !error && <p className="muted">Loading…</p>}

          {d && inc && (
            <>
              <p className="lede">{inc.explanation}</p>

              <section>
                <h3>Incident</h3>
                <dl className="kv">
                  <dt>Entity</dt>
                  <dd className="mono">
                    {inc.entity.type}: {inc.entity.key}
                  </dd>
                  <dt>Source → destination</dt>
                  <dd className="mono">
                    {inc.src_ip ?? "many"}:{inc.src_port ?? "-"} → {inc.dst_ip ?? "many"}:{inc.dst_port ?? "-"}{" "}
                    ({inc.protocol ?? "n/a"})
                  </dd>
                  <dt>Confidence</dt>
                  <dd>{confidenceLabel(inc)}</dd>
                  <dt>Method / detector</dt>
                  <dd>
                    {humanize(inc.detection_method)} / {inc.detector_version}
                  </dd>
                  <dt>Model</dt>
                  <dd>
                    {inc.model_version ?? "none (rules or statistics)"} - eligible:{" "}
                    {String(inc.evidence.model_eligibility.eligible)}
                    {inc.evidence.model_eligibility.reason ? ` (${inc.evidence.model_eligibility.reason})` : ""}
                  </dd>
                  <dt>Feature schema</dt>
                  <dd>{inc.feature_schema_version}</dd>
                  <dt>Window</dt>
                  <dd>
                    {fmtTime(inc.window_start)} – {fmtTime(inc.window_end)}
                  </dd>
                  <dt>First / last seen</dt>
                  <dd>
                    {fmtTime(inc.first_seen)} / {fmtTime(inc.last_seen)}
                  </dd>
                  <dt>Capture time of evidence</dt>
                  <dd>
                    {fmtTime(inc.event_time)}
                    {inc.replay_run_id ? ` (replay ${inc.replay_run_id})` : ""}
                  </dd>
                  <dt>Coverage</dt>
                  <dd>{humanize(inc.evidence.visibility.observation_coverage)}</dd>
                  <dt>Unavailable features</dt>
                  <dd className={inc.evidence.visibility.unavailable_features.length ? undefined : "dim"}>
                    {inc.evidence.visibility.unavailable_features.join(", ") || "none"}
                  </dd>
                  <dt>Capped (lower-bound) features</dt>
                  <dd className={inc.evidence.visibility.capped_features.length ? undefined : "dim"}>
                    {inc.evidence.visibility.capped_features.join(", ") || "none"}
                  </dd>
                </dl>
              </section>

              <KV title="Observed" data={inc.evidence.observed} />
              <KV title="Thresholds" data={inc.evidence.thresholds} />
              <KV title="Baseline" data={inc.evidence.baseline} />

              {inc.top_features.length > 0 && (
                <section>
                  <h3>Top features</h3>
                  <div className="feat">
                    {inc.top_features.map((f) => (
                      <div className="feat-row" key={f.name}>
                        <span className="mono">{f.name}</span>
                        <span className="nums">
                          {f.value === null ? (
                            <span className="dim">unavailable</span>
                          ) : (
                            `${Number(f.value.toFixed(4))} ${f.unit ?? ""}`
                          )}
                        </span>
                        <span className="nums muted">
                          {f.contribution === null ? "rule" : f.contribution.toFixed(3)}
                        </span>
                        <span className="bar-mini">
                          <i style={{ width: `${(Math.abs(f.contribution ?? 0) / maxContribution) * 100}%` }} />
                        </span>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              <section>
                <h3>Timeline</h3>
                <ol className="timeline">
                  {d.updates.map((u) => (
                    <li key={u.update_id}>
                      <b>#{u.update_seq}</b> {u.status} ({u.severity}) - {fmtCount(u.evidence.evidence_count)} pieces of
                      evidence
                      <div className="dim small">{fmtTime(u.timestamp)}</div>
                    </li>
                  ))}
                </ol>
              </section>

              <section>
                <h3>
                  Related raw events ({d.related_events.length}
                  {inc.evidence.raw_event_ids_truncated ? ", truncated" : ""})
                </h3>
                {d.related_events.map((e, i) => (
                  <pre key={i} className="raw">
                    {JSON.stringify(e, null, 2)}
                  </pre>
                ))}
                {d.related_events.length === 0 && <p className="muted small">No raw events were retained.</p>}
              </section>
            </>
          )}
        </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
