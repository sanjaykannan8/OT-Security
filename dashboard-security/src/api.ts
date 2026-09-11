import type { IncidentDetail, IncidentRow, Stats } from "./types";

export class HistoryUnavailable extends Error {}
export class Unauthorized extends Error {}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url, { credentials: "same-origin" });
  if (r.status === 401) throw new Unauthorized("login required");
  if (r.status === 503) throw new HistoryUnavailable("history store unavailable");
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return (await r.json()) as T;
}

async function post<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Requested-With": "sih-ui" },
    body: JSON.stringify(body),
  });
  if (r.status === 401) throw new Unauthorized("invalid credentials");
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return (await r.json()) as T;
}

export interface Me {
  user: string;
  role: string;
  disclaimer: string;
}

export interface Filters {
  severity: string;
  threat_class: string;
  status: string;
  q: string;
  since_minutes: number;
}

export const api = {
  me: () => get<Me>("/api/me"),
  login: (username: string, password: string) => post<{ user: string; role: string }>("/api/login", { username, password }),
  logout: () => post<{ ok: boolean }>("/api/logout", {}),
  incidents: (f: Filters) => {
    const p = new URLSearchParams({
      severity: f.severity,
      threat_class: f.threat_class,
      status: f.status,
      q: f.q,
      since_minutes: String(f.since_minutes),
      limit: "300",
    });
    return get<{ items: IncidentRow[] }>(`/api/incidents?${p.toString()}`);
  },
  incident: (id: string) => get<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
  stats: (windowMinutes: number) => get<Stats>(`/api/stats?window_minutes=${windowMinutes}`),
};
