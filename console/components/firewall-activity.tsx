"use client";

import { ShieldCheck } from "lucide-react";
import { useConsole } from "@/components/console-data";
import { timeAgo } from "@/lib/format";
import type { DefenseKind } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Each defense gets a colour by what it caught, not by severity — an operator
 *  learns the palette faster than a severity scale. */
const KIND_DOT: Record<DefenseKind, string> = {
  policy: "bg-deny",
  trap: "bg-tripwire",
  trifecta: "bg-tripwire",
  exfil: "bg-held",
  identity: "bg-chart-4",
  gate: "bg-chart-4",
  rate: "bg-chart-5",
};

export function FirewallActivity({ limit }: { limit?: number }) {
  const { firewall, freshIds, nowTick } = useConsole();
  const shown = limit ? firewall.slice(0, limit) : firewall;

  if (firewall.length === 0) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2.5 px-5 py-10 text-center">
        <ShieldCheck className="text-muted-foreground/60 size-5" />
        <div className="text-[13px] font-medium">No defense has fired.</div>
        <p className="text-muted-foreground max-w-[30ch] text-[12.5px]">
          Tripwires, DLP scans and session pins report here when they catch something.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      {shown.map((e) => (
        <div
          key={e.id}
          className={cn(
            "border-border-soft flex gap-3 border-b px-[18px] py-3 last:border-b-0",
            freshIds.has(e.id) && "bg-accent/60 transition-colors",
          )}
        >
          <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", KIND_DOT[e.defense.kind])} />
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-1.5">
              <span className="truncate text-[12.5px]">{e.defense.label}</span>
              {e.occurrences > 1 && (
                <span className="text-muted-foreground text-[12.5px]">&times;{e.occurrences}</span>
              )}
              {e.shadow && (
                <span className="text-held-foreground text-[11px]">shadow · would block</span>
              )}
              <span className="text-muted-foreground ml-auto shrink-0 font-mono text-[11px]">
                {timeAgo(e.ts, nowTick)}
              </span>
            </div>
            <div className="text-muted-foreground mt-0.5 truncate font-mono text-[11.5px]">
              {e.agentId} · {e.tool}:{e.action}
              {e.target ? ` · ${e.target}` : ""}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
