import type { Decision, Severity } from "@/lib/types";

export function timeAgo(ts: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

/** Seconds left, as m:ss — the shape an approval countdown wants. */
export function countdown(untilMs: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((untilMs - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function secondsLeft(untilMs: number, now = Date.now()): number {
  return Math.max(0, Math.round((untilMs - now) / 1000));
}

export const decisionLabel: Record<Decision, string> = {
  allow: "allow",
  deny: "deny",
  require_approval: "held",
};

/** Risk and blast-radius severities reuse the decision colour vocabulary. */
export function severityTone(severity: Severity | undefined): Decision {
  if (severity === "high") return "deny";
  if (severity === "elevated") return "require_approval";
  return "allow";
}

export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}
