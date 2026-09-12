import { ArrowsClockwise, DownloadSimple, Question, WarningCircle } from "@phosphor-icons/react";
import type { View } from "./Sidebar";

export type StreamState = "connecting" | "live" | "reconnecting" | "resyncing";

const TITLES: Record<View, string> = {
  overview: "Overview",
  incidents: "Incidents",
  entities: "Entities",
  detections: "Detections",
};

const STREAM_COPY: Record<StreamState, string> = {
  connecting: "Connecting",
  live: "Live",
  reconnecting: "Reconnecting",
  resyncing: "Resyncing",
};

export function TopBar({
  view,
  stream,
  historyStale,
  onRefresh,
  onExport,
}: {
  view: View;
  stream: StreamState;
  historyStale: boolean;
  onRefresh: () => void;
  onExport: () => void;
}) {
  const tone = stream === "live" ? "is-live" : stream === "connecting" ? "is-waiting" : "is-down";

  return (
    <header className="topbar">
      <nav className="crumbs" aria-label="breadcrumb">
        Aegis OT <span className="sep">›</span> SOC <span className="sep">›</span> <b>{TITLES[view]}</b>
      </nav>

      <span className={`pill stream-chip ${tone}`} aria-live="polite">
        <i className="dot" />
        {STREAM_COPY[stream]}
      </span>

      {historyStale && (
        <span className="pill sev-high" title="Incidents shown are live-stream only until the store recovers.">
          <WarningCircle size={14} weight="fill" />
          History store unreachable
        </span>
      )}

      <span className="spacer" />

      <button className="icon-btn" onClick={onRefresh} title="Refresh now" aria-label="Refresh now">
        <ArrowsClockwise size={17} />
      </button>
      <a
        className="icon-btn"
        href="https://github.com/gowtham472/OT-Security"
        target="_blank"
        rel="noreferrer noopener"
        title="Documentation"
        aria-label="Documentation"
      >
        <Question size={17} />
      </a>
      <button className="btn btn-accent" onClick={onExport}>
        <DownloadSimple size={16} weight="bold" />
        Export evidence
      </button>
    </header>
  );
}
