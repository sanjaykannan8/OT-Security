import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { fmtCount } from "./format";

/** Round a maximum up to a readable axis top (1/2/5 x 10^n). */
function niceMax(v: number): number {
  if (v <= 5) return 5;
  const mag = 10 ** Math.floor(Math.log10(v));
  const step = [1, 2, 2.5, 5, 10].find((s) => v <= s * mag) ?? 10;
  return step * mag;
}

const PAD_L = 44;
const PAD_B = 28;
const PAD_T = 14;

export interface BarPoint {
  label: string;
  n: number;
  /** Long-form label for the tooltip, e.g. the full timestamp. */
  title: string;
}

/**
 * Measure the element we draw into. The SVG is absolutely positioned in CSS so it never
 * feeds its own height back into the flex row - otherwise the chart and its container
 * would chase each other.
 */
function useBox(ref: React.RefObject<HTMLElement | null>) {
  const [box, setBox] = useState({ w: 640, h: 250 });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) setBox({ w: Math.round(width), h: Math.round(height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return box;
}

/**
 * Vertical bar chart drawn at the true pixel size of its container, so it fills whatever
 * height the row gives it instead of letterboxing. One scale places the bars, the
 * gridlines and every tick label; the tallest bar is emphasised, and hovering any bar
 * reads out its exact value.
 */
export function BarChart({ points, unit }: { points: BarPoint[]; unit: string }) {
  const gid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const [hot, setHot] = useState<number | null>(null);
  const host = useRef<HTMLDivElement | null>(null);
  const { w: W, h: H } = useBox(host);

  // Drop the hover if the series shrinks beneath it.
  useEffect(() => {
    if (hot !== null && hot >= points.length) setHot(null);
  }, [hot, points.length]);

  const top = niceMax(Math.max(...points.map((p) => p.n), 1));
  const plotW = Math.max(40, W - PAD_L);
  const plotH = Math.max(40, H - PAD_B - PAD_T);
  const slot = plotW / Math.max(1, points.length);
  const barW = Math.max(5, Math.min(40, slot * 0.56));
  const peak = points.length > 0 ? points.reduce((best, p, i) => (p.n > points[best].n ? i : best), 0) : 0;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(top * f));
  const y = (n: number) => PAD_T + plotH - (n / top) * plotH;
  const cx = (i: number) => PAD_L + slot * i + slot / 2;
  // Show as many x labels as fit without crowding, but never fewer than four.
  const labelEvery = Math.max(1, Math.ceil(points.length / Math.max(4, Math.floor(plotW / 96))));

  const shown = Math.min(hot ?? peak, Math.max(0, points.length - 1));
  const active = points[shown];

  return (
    <div className="chart" ref={host}>
      {points.length === 0 || !active ? (
        <p className="muted small">No activity in this window.</p>
      ) : (
        <>
          <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${unit} over time`}>
            <defs>
              <linearGradient id={`aegis-bar-${gid}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent)" />
                <stop offset="70%" stopColor="var(--accent-3)" />
                <stop offset="100%" stopColor="#ffffff" />
              </linearGradient>
            </defs>

            {ticks.map((t) => (
              <g key={t}>
                <line className="grid-line" x1={PAD_L} y1={y(t)} x2={W} y2={y(t)} />
                <text className="axis" x={PAD_L - 10} y={y(t) + 4} textAnchor="end">
                  {t >= 1000 ? `${t / 1000}k` : t}
                </text>
              </g>
            ))}

            {points.map((p, i) => {
              const h = Math.max(2, plotH - (y(p.n) - PAD_T));
              const isHot = i === shown;
              const r = Math.min(6, barW / 2);
              const x = cx(i) - barW / 2;
              const yTop = PAD_T + plotH - h;
              return (
                <g key={p.label + i}>
                  <path
                    className="bar"
                    style={isHot ? { fill: `url(#aegis-bar-${gid})` } : undefined}
                    d={`M${x} ${PAD_T + plotH} V${yTop + r} a${r} ${r} 0 0 1 ${r} ${-r} h${barW - 2 * r} a${r} ${r} 0 0 1 ${r} ${r} V${PAD_T + plotH} Z`}
                  />
                  {isHot && <circle className="bar-cap" cx={cx(i)} cy={yTop} r={5} />}
                  <rect
                    className="bar-hit"
                    x={cx(i) - slot / 2}
                    y={PAD_T}
                    width={slot}
                    height={plotH}
                    onMouseEnter={() => setHot(i)}
                    onMouseLeave={() => setHot(null)}
                  >
                    <title>{`${p.title}: ${fmtCount(p.n)} ${unit}`}</title>
                  </rect>
                </g>
              );
            })}

            {points.map((p, i) =>
              i % labelEvery === 0 ? (
                <text key={`x${i}`} className="axis" x={cx(i)} y={H - 8} textAnchor="middle">
                  {p.label}
                </text>
              ) : null,
            )}
          </svg>

          <div className="tooltip" style={{ left: `${(cx(shown) / W) * 100}%`, top: `${(y(active.n) / H) * 100}%` }}>
            <div className="when">{active.title}</div>
            <dl>
              <dt>{unit}</dt>
              <dd>{fmtCount(active.n)}</dd>
              <dt>Window peak</dt>
              <dd>{fmtCount(points[peak].n)}</dd>
            </dl>
          </div>
        </>
      )}
    </div>
  );
}

/** Horizontal distribution bars, for categorical counts with long labels. */
export function HBars({ items }: { items: { label: string; n: number }[] }) {
  if (items.length === 0) return <p className="muted small">Nothing recorded in this window.</p>;
  const max = Math.max(1, ...items.map((i) => i.n));
  return (
    <div className="hbars">
      {items.map((it) => (
        <div className="hbar" key={it.label}>
          <span className="label" title={it.label}>
            {it.label}
          </span>
          <span className="track">
            <span className="fill" style={{ width: `${(it.n / max) * 100}%` }} />
          </span>
          <span className="n">{fmtCount(it.n)}</span>
        </div>
      ))}
    </div>
  );
}
