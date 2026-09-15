"use client";

import { useMemo, useState } from "react";

interface Row {
  ts: number;
  decision: string;
}

/** Verdict = a status encoding (state, not identity). Fixed order, each ships
 *  with a label, coloured by the shared semantic tokens. */
const KINDS = [
  { key: "allow", label: "Allowed", test: (d: string) => d === "allow" },
  { key: "appr", label: "Held", test: (d: string) => d === "require_approval" },
  { key: "deny", label: "Denied", test: (d: string) => d === "deny" },
] as const;

const VB_W = 1000;
const VB_H = 150;
const PAD_B = 22; // room for the hour axis
const PAD_T = 8;

/** Requests over the window, bucketed by hour and stacked by verdict — a spike
 *  in denials is the signal an operator watches for. */
export function Timeline({ requests, windowHours, now }: { requests: Row[]; windowHours: number; now: number }) {
  const [hover, setHover] = useState<number | null>(null);

  const { buckets, max, bucketMs, start } = useMemo(() => {
    const n = Math.max(1, Math.min(windowHours, 48));
    const bucketMs = 3_600_000; // 1 hour
    const end = Math.ceil(now / bucketMs) * bucketMs;
    const start = end - n * bucketMs;
    const buckets = Array.from({ length: n }, (_, i) => ({
      t0: start + i * bucketMs,
      allow: 0,
      appr: 0,
      deny: 0,
      total: 0,
    }));
    for (const r of requests) {
      if (r.ts < start || r.ts >= end) continue;
      const idx = Math.floor((r.ts - start) / bucketMs);
      const b = buckets[idx];
      if (!b) continue;
      const kind = KINDS.find((k) => k.test(r.decision));
      if (!kind) continue;
      b[kind.key] += 1;
      b.total += 1;
    }
    const max = Math.max(1, ...buckets.map((b) => b.total));
    return { buckets, max, bucketMs, start };
  }, [requests, windowHours, now]);

  const plotH = VB_H - PAD_B - PAD_T;
  const bw = VB_W / buckets.length;
  const gap = Math.min(3, bw * 0.18);
  const totalReq = buckets.reduce((s, b) => s + b.total, 0);

  // recessive gridlines at 0 / mid / max
  const gridVals = max <= 2 ? [0, max] : [0, Math.round(max / 2), max];
  const y = (v: number) => PAD_T + plotH - (v / max) * plotH;

  const fmtHour = (t: number) =>
    new Date(t).toLocaleTimeString([], { hour: "numeric", hour12: true }).replace(" ", "").toLowerCase();

  if (totalReq === 0) {
    return <div className="empty">No requests in the last {windowHours}h yet — the timeline fills as traffic flows.</div>;
  }

  return (
    <div className="tl">
      <div className="tl-head">
        <div className="tl-legend">
          {KINDS.map((k) => (
            <span className="tl-leg" key={k.key}>
              <span className={`tl-dot ${k.key}`} />
              {k.label}
            </span>
          ))}
        </div>
        <span className="tl-peak">peak {max}/h</span>
      </div>

      <div className="tl-plot">
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} preserveAspectRatio="none" className="tl-svg" role="img" aria-label={`Requests per hour over the last ${windowHours} hours`}>
          {gridVals.map((v) => (
            <g key={v}>
              <line className="tl-grid" x1="0" x2={VB_W} y1={y(v)} y2={y(v)} />
            </g>
          ))}
          {buckets.map((b, i) => {
            const x = i * bw + gap / 2;
            const w = bw - gap;
            let cursor = PAD_T + plotH;
            const segs = (["allow", "appr", "deny"] as const)
              .map((key) => {
                const val = b[key];
                if (val === 0) return null;
                const h = (val / max) * plotH;
                cursor -= h;
                return { key, y: cursor, h };
              })
              .filter(Boolean) as Array<{ key: string; y: number; h: number }>;
            return (
              <g key={b.t0} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover((h) => (h === i ? null : h))}>
                {/* invisible full-height hit target */}
                <rect x={i * bw} y={PAD_T} width={bw} height={plotH} fill="transparent" />
                {segs.map((s, si) => (
                  <rect
                    key={s.key}
                    className={`tl-bar ${s.key}${hover === i ? " hot" : ""}`}
                    x={x}
                    y={s.y}
                    width={w}
                    height={Math.max(0, s.h - (si < segs.length - 1 ? 2 : 0))}
                    rx="2.5"
                  />
                ))}
              </g>
            );
          })}
        </svg>

        {hover !== null && buckets[hover] && buckets[hover].total > 0 && (
          <div className="tl-tip" style={{ left: `${((hover + 0.5) / buckets.length) * 100}%` }}>
            <div className="tl-tip-t">
              {fmtHour(buckets[hover].t0)}–{fmtHour(buckets[hover].t0 + bucketMs)}
            </div>
            {KINDS.map((k) =>
              buckets[hover]![k.key] > 0 ? (
                <div className="tl-tip-r" key={k.key}>
                  <span className={`tl-dot ${k.key}`} />
                  {k.label}
                  <b>{buckets[hover]![k.key]}</b>
                </div>
              ) : null,
            )}
          </div>
        )}
      </div>

      <div className="tl-axis">
        <span>{fmtHour(start)}</span>
        <span>now</span>
      </div>
    </div>
  );
}
