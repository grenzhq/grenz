import { cn } from "@/lib/utils";
import { decisionLabel } from "@/lib/format";
import type { Decision } from "@/lib/types";

const TONE: Record<Decision, string> = {
  allow: "border-allow/30 bg-allow/10 text-allow-foreground",
  deny: "border-deny/30 bg-deny/10 text-deny-foreground",
  require_approval: "border-held/30 bg-held/10 text-held-foreground",
};

const DOT: Record<Decision, string> = {
  allow: "bg-allow",
  deny: "bg-deny",
  require_approval: "bg-held",
};

/**
 * The one place a verdict is rendered.
 *
 * `require_approval` reads as "held" to a human: the request is at the door,
 * not refused, and not through. Its own token set means a brand-colour change
 * can never repaint a decision.
 */
export function DecisionBadge({
  decision,
  children,
  className,
}: {
  decision: Decision;
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border py-0.5 pr-2 pl-1.5 text-[11.5px] font-medium whitespace-nowrap",
        TONE[decision],
        className,
      )}
    >
      <span className={cn("size-[5px] shrink-0 rounded-full", DOT[decision])} />
      {children ?? decisionLabel[decision]}
    </span>
  );
}
