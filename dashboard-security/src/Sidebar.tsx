import {
  Broadcast,
  ChartLineUp,
  type Icon,
  MagnifyingGlass,
  ScrollIcon,
  ShieldWarning,
  SignOut,
  SquaresFour,
  Stack,
  WarningOctagon,
} from "@phosphor-icons/react";
import type { Me } from "./api";
import { BrandLockup } from "./brand";

export type View = "overview" | "incidents" | "entities" | "detections";

const PRIMARY: { id: View; label: string; icon: Icon }[] = [
  { id: "overview", label: "Overview", icon: SquaresFour },
  { id: "incidents", label: "Incidents", icon: ShieldWarning },
  { id: "entities", label: "Entities", icon: Stack },
  { id: "detections", label: "Detections", icon: ChartLineUp },
];

export function Sidebar({
  view,
  onView,
  counts,
  me,
  onLogout,
  query,
  onQuery,
  searchRef,
}: {
  view: View;
  onView: (v: View) => void;
  counts: { incidents: number; entities: number };
  me: Me;
  onLogout: () => void;
  query: string;
  onQuery: (q: string) => void;
  searchRef: React.RefObject<HTMLInputElement | null>;
}) {
  const count = (id: View) =>
    id === "incidents" ? counts.incidents : id === "entities" ? counts.entities : undefined;

  return (
    <aside className="sidebar">
      <BrandLockup />

      <div className="field">
        <MagnifyingGlass size={16} weight="bold" />
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          placeholder="Search entity or reason"
          aria-label="search incidents"
          maxLength={128}
        />
        <kbd className="keycap">⌘K</kbd>
      </div>

      <nav className="nav" aria-label="sections">
        {PRIMARY.map(({ id, label, icon: Glyph }) => (
          <button
            key={id}
            className="nav-item"
            aria-current={view === id ? "page" : undefined}
            onClick={() => onView(id)}
          >
            <Glyph size={18} weight={view === id ? "fill" : "regular"} />
            {label}
            {count(id) !== undefined && <span className="count">{count(id)}</span>}
          </button>
        ))}

        <p className="eyebrow nav-group">Platform</p>
        <a className="nav-item" href="http://127.0.0.1:3000" target="_blank" rel="noreferrer noopener">
          <Broadcast size={18} />
          Stream health
        </a>
        <a className="nav-item" href="http://127.0.0.1:3000" target="_blank" rel="noreferrer noopener">
          <ScrollIcon size={18} />
          Audit log
        </a>
      </nav>

      <section className="notice">
        <h4>
          <WarningOctagon size={15} weight="fill" className="sev-high" />
          Passive · offline simulation
        </h4>
        <p>Intelligence only. Nothing is probed, decrypted or sent back to the monitored side.</p>
        <details>
          <summary>Read the full scope</summary>
          <p>{me.disclaimer}</p>
        </details>
      </section>

      <div className="who">
        <span className="avatar">{me.user.slice(0, 1).toUpperCase()}</span>
        <div>
          <div className="who-name">{me.user}</div>
          <div className="who-role">{me.role}</div>
        </div>
        <button className="icon-btn sm" onClick={onLogout} title="Sign out" aria-label="Sign out">
          <SignOut size={15} />
        </button>
      </div>
    </aside>
  );
}
