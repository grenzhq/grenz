"use client";

import { Card, CardContent } from "@/components/ui/card";
import { useConsole } from "@/components/console-data";
import { EmptyNote, PageHeader } from "@/components/page-header";
import { cn } from "@/lib/utils";

function Meter({ spent, limit }: { spent: number; limit: number }) {
  const pct = limit > 0 ? Math.min(100, (spent / limit) * 100) : 0;
  return (
    <div className="bg-muted h-1.5 w-full overflow-hidden rounded-full">
      <div
        className={cn(
          "h-full rounded-full",
          pct >= 100 ? "bg-deny" : pct >= 80 ? "bg-held" : "bg-primary",
        )}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export default function BudgetsPage() {
  const { budgets } = useConsole();
  const withLimits = budgets.filter((b) => b.limit !== null || b.upstreams.length > 0);

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Budgets">
        Request ceilings per agent and per upstream, over the last hour. Exhausting a budget denies
        the next request rather than queuing it.
      </PageHeader>

      <Card className="min-w-0 gap-0 overflow-hidden py-0">
        <CardContent className="px-0">
          {withLimits.length === 0 ? (
            <EmptyNote>No budgets set — nothing is capped.</EmptyNote>
          ) : (
            withLimits.map((b) => (
              <div
                key={b.agent}
                className="border-border-soft flex flex-col gap-2.5 border-b px-[18px] py-3.5 last:border-b-0"
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-[12.5px] font-medium">{b.agent}</span>
                  {b.override && (
                    <span className="border-held/30 bg-held/10 text-held-foreground rounded-full border px-2 py-0.5 text-[11px] font-medium">
                      override
                    </span>
                  )}
                  <span className="text-muted-foreground ml-auto font-mono text-[11.5px]">
                    {b.spent}/{b.limit ?? "unlimited"}
                  </span>
                </div>
                {b.limit !== null && <Meter spent={b.spent} limit={b.limit} />}
                {b.upstreams.map((u) => (
                  <div key={u.upstream} className="flex flex-col gap-1.5 pl-3">
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground font-mono text-[11.5px]">
                        {u.upstream}
                      </span>
                      <span className="text-muted-foreground ml-auto font-mono text-[11.5px]">
                        {u.spent}/{u.limit}
                      </span>
                    </div>
                    <Meter spent={u.spent} limit={u.limit} />
                  </div>
                ))}
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
