"use client";

import { CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useConsole } from "@/components/console-data";
import { countdown } from "@/lib/format";

/**
 * The only panel on the console that costs you something to ignore: an approval
 * left unanswered expires to a denial, so the countdown is the headline, not a
 * detail.
 */
export function AwaitingYou({ limit }: { limit?: number }) {
  const { approvals, busy, decide, nowTick } = useConsole();
  const shown = limit ? approvals.slice(0, limit) : approvals;

  if (approvals.length === 0) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2.5 px-5 py-10 text-center">
        <CheckCircle2 className="text-muted-foreground/60 size-5" />
        <div className="text-[13px] font-medium">Nothing waiting on you.</div>
        <p className="text-muted-foreground max-w-[30ch] text-[12.5px]">
          Anything the policy holds for a human shows up here.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      {shown.map((a) => (
        <div key={a.id} className="border-border-soft border-b px-[18px] py-3.5 last:border-b-0">
          <div className="flex items-center gap-2">
            <span className="truncate font-mono text-[12.5px] font-medium">
              {a.tool}:{a.action}
            </span>
            <span className="text-held-foreground ml-auto font-mono text-[11.5px] tabular-nums">
              {countdown(a.expiresAt, nowTick)}
            </span>
          </div>
          <div className="text-muted-foreground mt-1.5 truncate font-mono text-[11.5px]" title={a.target}>
            {a.target || a.agentId}
          </div>
          <div className="mt-2.5 flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="border-allow/30 bg-allow/10 text-allow-foreground hover:bg-allow/18 hover:text-allow-foreground h-[29px] flex-1"
              disabled={busy === a.id}
              onClick={() => void decide(a.id, "approve")}
            >
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="h-[29px] flex-1"
              disabled={busy === a.id}
              onClick={() => void decide(a.id, "deny")}
            >
              Deny
            </Button>
          </div>
        </div>
      ))}
      {limit && approvals.length > limit && (
        <div className="text-muted-foreground border-t px-[18px] py-2.5 text-xs">
          {approvals.length - limit} more waiting.
        </div>
      )}
    </div>
  );
}
