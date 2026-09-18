"use client";

import Link from "next/link";
import { ArrowRight, MousePointerClick, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DecisionBadge } from "@/components/decision-badge";
import type { RequestRow } from "@/lib/types";

const DECISION_LABEL: Record<RequestRow["decision"], string> = {
  allow: "Allowed",
  deny: "Denied",
  require_approval: "Held for approval",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-muted-foreground w-[92px] shrink-0 text-xs">{label}</span>
      <span className="min-w-0 flex-1 text-[12.5px]">{children}</span>
    </div>
  );
}

/**
 * One decision in full, plus the two things you'd actually do about it: change
 * the rule, or act on the agent. It sits beside the table rather than over it,
 * so comparing the selected row with the ones around it stays possible.
 */
export function RequestDetail({ req, onClose }: { req: RequestRow | null; onClose: () => void }) {
  if (!req) {
    return (
      <div className="text-muted-foreground flex flex-1 flex-col items-center justify-center gap-2.5 px-6 text-center">
        <MousePointerClick className="size-5 opacity-60" />
        <p className="max-w-[26ch] text-[12.5px]">
          Pick a request to see what the policy said about it.
        </p>
      </div>
    );
  }

  const when = new Date(req.ts).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });
  const result = req.forwarded ? `forwarded · ${req.status ?? "—"}` : "blocked at the door";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2.5 border-b px-[18px] py-3.5">
        <span className="truncate font-mono text-[13.5px] font-medium">
          {req.tool}:{req.action}
        </span>
        <DecisionBadge decision={req.decision}>{DECISION_LABEL[req.decision]}</DecisionBadge>
        <Button
          variant="ghost"
          size="icon"
          className="ml-auto size-[26px] shrink-0"
          onClick={onClose}
          aria-label="Close detail panel"
        >
          <X className="size-3.5" />
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <div className="border-border-soft border-b px-[18px] py-3.5">
          <div className="text-muted-foreground text-[11.5px] font-medium">Target as written</div>
          <pre className="bg-card-inset mt-2 rounded-lg border px-3 py-2.5 font-mono text-[11.5px] leading-relaxed break-all whitespace-pre-wrap">
            {req.target || "—"}
          </pre>
        </div>

        <div className="border-border-soft flex flex-col gap-2.5 border-b px-[18px] py-3.5">
          <Field label="Agent">{req.agentId}</Field>
          <Field label="Tool">
            <span className="font-mono">{req.tool}</span>
          </Field>
          {req.upstream && (
            <Field label="Upstream">
              <span className="font-mono">{req.upstream}</span>
            </Field>
          )}
          {req.method && (
            <Field label="Method">
              <span className="font-mono">{req.method}</span>
            </Field>
          )}
          <Field label="Reason code">
            <span className="font-mono">{req.reason}</span>
          </Field>
          <Field label="Result">
            <span className="font-mono">{result}</span>
          </Field>
          <Field label="When">{when}</Field>
        </div>

        <div className="flex flex-col gap-1 px-[18px] py-3.5">
          <div className="text-muted-foreground text-[11.5px] font-medium">Act on this</div>
          <Link
            href="/policy"
            className="text-primary hover:bg-accent -mx-2 flex items-center gap-1.5 rounded-md px-2 py-1.5 text-[12.5px] font-medium"
          >
            Change the rule for{" "}
            <span className="font-mono">
              {req.tool}:{req.action}
            </span>
            <ArrowRight className="size-3.5" />
          </Link>
          <Link
            href="/access"
            className="text-primary hover:bg-accent -mx-2 flex items-center gap-1.5 rounded-md px-2 py-1.5 text-[12.5px] font-medium"
          >
            Manage <span className="font-mono">{req.agentId}</span>
            <ArrowRight className="size-3.5" />
          </Link>
        </div>
      </div>
    </div>
  );
}
