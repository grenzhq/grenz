"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useConsole } from "@/components/console-data";
import { AwaitingYou } from "@/components/awaiting-you";
import { EmptyNote, PageHeader } from "@/components/page-header";

export default function ApprovalsPage() {
  const { approvals, summary } = useConsole();
  const wouldBlock = summary?.would_block ?? [];

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Approvals">
        Requests the policy holds for a human. Each expires to a denial five minutes after it
        arrives — silence is a refusal, not a pass.
      </PageHeader>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card className="border-held/30 flex min-w-0 flex-col gap-0 overflow-hidden py-0">
          <CardHeader className="px-[18px] py-3.5">
            <CardTitle className="flex items-center gap-2 text-[14.5px]">
              Waiting now
              {approvals.length > 0 && (
                <span className="bg-held/15 text-held-foreground inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[11px] font-semibold">
                  {approvals.length}
                </span>
              )}
            </CardTitle>
            <CardDescription className="text-[12.5px]">
              Approving lets this one request through; it grants nothing standing.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col border-t px-0">
            <AwaitingYou />
          </CardContent>
        </Card>

        <Card className="flex min-w-0 flex-col gap-0 overflow-hidden py-0">
          <CardHeader className="px-[18px] py-3.5">
            <CardTitle className="text-[14.5px]">Shadow would-block</CardTitle>
            <CardDescription className="text-[12.5px]">
              What a stricter policy would have stopped, counted but not enforced.
            </CardDescription>
          </CardHeader>
          <CardContent className="border-t px-0">
            {wouldBlock.length === 0 ? (
              <EmptyNote>Nothing is running in shadow mode.</EmptyNote>
            ) : (
              wouldBlock.map((w, i) => (
                <div
                  key={`${w.tool}-${w.action}-${i}`}
                  className="border-border-soft flex items-center gap-3 border-b px-[18px] py-3 last:border-b-0"
                >
                  <span className="truncate font-mono text-[12.5px]">
                    {w.tool}:{w.action}
                  </span>
                  <span className="text-muted-foreground ml-auto shrink-0 font-mono text-[11.5px]">
                    would-{w.decision} &times; {w.n}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
