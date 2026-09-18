"use client";

import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import type { RequestRow } from "@/lib/types";

const CONFIG = {
  allow: { label: "Allowed", color: "var(--allow)" },
  held: { label: "Held", color: "var(--held)" },
  deny: { label: "Denied", color: "var(--deny)" },
} satisfies ChartConfig;

function fmtHour(t: number): string {
  return new Date(t).toLocaleTimeString([], { hour: "numeric", hour12: true }).replace(" ", "").toLowerCase();
}

/**
 * Requests per hour over the window, stacked by verdict.
 *
 * Stacked rather than one total line because the shape an operator watches for
 * is a denial spike inside otherwise normal traffic — a single throughput line
 * hides exactly the event worth seeing.
 */
export function ThroughputChart({
  requests,
  windowHours,
  now,
}: {
  requests: RequestRow[];
  windowHours: number;
  now: number;
}) {
  const buckets = useMemo(() => {
    const n = Math.max(1, Math.min(windowHours, 48));
    const bucketMs = 3_600_000;
    const end = Math.ceil(now / bucketMs) * bucketMs;
    const start = end - n * bucketMs;
    const out = Array.from({ length: n }, (_, i) => ({
      t: start + i * bucketMs,
      allow: 0,
      held: 0,
      deny: 0,
      total: 0,
    }));
    for (const r of requests) {
      if (r.ts < start || r.ts >= end) continue;
      const b = out[Math.floor((r.ts - start) / bucketMs)];
      if (!b) continue;
      if (r.decision === "allow") b.allow += 1;
      else if (r.decision === "deny") b.deny += 1;
      else b.held += 1;
      b.total += 1;
    }
    return out;
  }, [requests, windowHours, now]);

  const peak = Math.max(0, ...buckets.map((b) => b.total));

  if (peak === 0) {
    return (
      <div className="text-muted-foreground flex h-[184px] items-center justify-center text-[13px]">
        No requests in the last {windowHours}h yet — this fills as traffic flows.
      </div>
    );
  }

  return (
    <ChartContainer config={CONFIG} className="h-[184px] w-full">
      {/* The side margins are not decoration: without them a spike in the first
          or last bucket — the one that just happened, the one you are watching
          for — is drawn half outside the plot and reads as an empty chart. */}
      <AreaChart data={buckets} margin={{ left: 4, right: 4, top: 6, bottom: 0 }}>
        <defs>
          {(["allow", "held", "deny"] as const).map((k) => (
            <linearGradient key={k} id={`fill-${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={`var(--color-${k})`} stopOpacity={0.28} />
              <stop offset="100%" stopColor={`var(--color-${k})`} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid vertical={false} strokeDasharray="0" stroke="var(--border-soft)" />
        <XAxis
          dataKey="t"
          tickLine={false}
          axisLine={false}
          tickMargin={10}
          minTickGap={48}
          tickFormatter={fmtHour}
          className="font-mono text-[10.5px]"
        />
        <ChartTooltip
          content={<ChartTooltipContent labelFormatter={(_, p) => fmtHour(Number(p?.[0]?.payload?.t))} indicator="dot" />}
        />
        {(["deny", "held", "allow"] as const).map((k) => (
          <Area
            key={k}
            dataKey={k}
            type="monotone"
            stackId="v"
            stroke={`var(--color-${k})`}
            strokeWidth={1.75}
            fill={`url(#fill-${k})`}
          />
        ))}
      </AreaChart>
    </ChartContainer>
  );
}
