/** Display formatting. Nothing here invents a value: unavailable stays unavailable. */

/** Full timestamp, to the second. Used where an operator needs the exact instant. */
export function fmtTime(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

/** Compact relative age, e.g. "just now", "4m", "3h", "2d". */
export function fmtAge(ts: string, now: number = Date.now()): string {
  const d = new Date(ts).getTime();
  if (Number.isNaN(d)) return ts;
  const s = Math.max(0, Math.round((now - d) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

/** Thousands separators, no forced decimals. */
export function fmtCount(n: number): string {
  return n.toLocaleString("en-US");
}

/** Byte counts at a human scale. */
export function fmtBytes(n: number): string {
  const units = ["B", "kB", "MB", "GB", "TB"];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

/** Large plain numbers at a human scale, e.g. 8421.5 -> "8.4k". */
export function fmtCompact(n: number): string {
  const abs = Math.abs(n);
  if (abs >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (abs >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (abs >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return abs >= 100 ? Math.round(n).toString() : Number(n.toFixed(2)).toString();
}

/** Evidence values arrive as loose JSON; render each kind at a sensible precision. */
export function fmtEvidence(key: string, value: unknown): string {
  if (value === null || value === undefined) return "unavailable";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value !== "number") return String(value);
  if (/bytes|octets/i.test(key)) return fmtBytes(value);
  // Rates first: "packets_per_s" also ends in _s, but it is a rate, not a duration.
  if (/per_s|_rate$|_rate_|pps/i.test(key)) return `${fmtCompact(value)}/s`;
  if (/_ms$/i.test(key)) return `${Number(value.toFixed(0))} ms`;
  if (/_s$|seconds|duration|interval/i.test(key)) return `${Number(value.toFixed(2))} s`;
  return fmtCompact(value);
}

/** Latency samples arrive in either milliseconds or seconds depending on the source. */
export function fmtLatency(ms: number | null | undefined, s: number | undefined): string {
  const x = ms ?? (s !== undefined ? s * 1000 : null);
  if (x === null) return "n/a";
  return x < 1000 ? `${Math.round(x)} ms` : `${(x / 1000).toFixed(2)} s`;
}

/**
 * Confidence is deliberately verbose: a heuristic score must never be shown as if it
 * were a calibrated probability.
 */
export function confidenceLabel(r: {
  confidence: number | null;
  confidence_kind: string;
  calibration_status: string;
}): string {
  if (r.confidence === null || r.confidence_kind === "unavailable") return "unavailable";
  const kind = r.confidence_kind === "calibrated_probability" ? "prob." : "score";
  const cal = r.calibration_status === "calibrated" ? "" : ` (${r.calibration_status.replace(/_/g, " ")})`;
  return `${r.confidence.toFixed(2)} ${kind}${cal}`;
}

/** snake_case identifiers read badly in a UI; title them without losing the term of art. */
export function humanize(s: string): string {
  return s.replace(/_/g, " ");
}
