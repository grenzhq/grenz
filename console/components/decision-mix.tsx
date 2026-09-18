import { formatCount } from "@/lib/format";
import type { Summary } from "@/lib/types";
import { cn } from "@/lib/utils";

const MIN_SEGMENT_PCT = 0.4;

/** Every verdict the engine reached, as a segmented bar plus the exact counts.
 *  The bar carries the proportion; the rows carry the numbers, because at 92%
 *  allowed the small segments are unreadable on their own. */
export function DecisionMix({ summary }: { summary: Summary | null }) {
  const total = summary?.total ?? 0;
  const rows = [
    { key: "allow", label: "Allowed", n: summary?.allow ?? 0, dot: "bg-allow" },
    { key: "deny", label: "Denied", n: summary?.deny ?? 0, dot: "bg-deny" },
    { key: "granted", label: "Approved by you", n: summary?.approvalGranted ?? 0, dot: "bg-held" },
    { key: "expired", label: "Expired to deny", n: summary?.approvalExpired ?? 0, dot: "bg-chart-5" },
  ];

  if (total === 0) {
    return (
      <p className="text-muted-foreground mt-4 text-[13px]">
        Nothing decided yet in this window.
      </p>
    );
  }

  return (
    <>
      <div className="mt-4 flex h-2 gap-0.5">
        {rows.map((r) => {
          const pct = (r.n / total) * 100;
          if (pct === 0) return null;
          return (
            <span
              key={r.key}
              className={cn("rounded-[3px] first:rounded-l-full last:rounded-r-full", r.dot)}
              style={{ width: `${Math.max(pct, MIN_SEGMENT_PCT)}%` }}
            />
          );
        })}
      </div>

      <div className="mt-4 flex flex-col">
        {rows.map((r) => (
          <div
            key={r.key}
            className="border-border-soft flex items-center gap-2.5 border-b py-2.5 last:border-b-0"
          >
            <span className={cn("size-[7px] rounded-[2px]", r.dot)} />
            <span className="text-secondary-foreground flex-1 text-[13px]">{r.label}</span>
            <span className="font-mono text-[13px]">{formatCount(r.n)}</span>
            <span className="text-muted-foreground w-11 text-right text-xs">
              {((r.n / total) * 100).toFixed(1)}%
            </span>
          </div>
        ))}
      </div>
    </>
  );
}
