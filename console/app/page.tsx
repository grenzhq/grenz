"use client";

import Link from "next/link";
import { AlertTriangle, ArrowRight, ArrowUpRight } from "lucide-react";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useConsole } from "@/components/console-data";
import { Stat, StatRow } from "@/components/stat-row";
import { ThroughputChart } from "@/components/throughput-chart";
import { DecisionMix } from "@/components/decision-mix";
import { AwaitingYou } from "@/components/awaiting-you";
import { FirewallActivity } from "@/components/firewall-activity";
import { RequestsTable } from "@/components/requests-table";
import { countdown, formatCount } from "@/lib/format";

const RECENT_ROWS = 10;

export default function OverviewPage() {
  const { summary, requests, approvals, online, nowTick } = useConsole();

  const windowHours = summary?.window_hours ?? 24;
  const total = summary?.total ?? 0;
  const allowN = summary?.allow ?? 0;
  const denyN = summary?.deny ?? 0;
  const pct = (n: number) => (total > 0 ? ((n / total) * 100).toFixed(1) : "0.0");

  // The soonest expiry is what makes the pending count urgent rather than
  // informational, so the stat footer carries it.
  const soonest = approvals.reduce<number | null>(
    (min, a) => (min === null || a.expiresAt < min ? a.expiresAt : min),
    null,
  );

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-[22px] font-semibold tracking-tight">Overview</h1>
        <p className="text-muted-foreground text-[13.5px]">
          Every request your agents make, decided the moment it happens. Nothing here left the proxy.
        </p>
      </div>

      {!online && (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertTitle>Can&rsquo;t reach the Grenz proxy.</AlertTitle>
          <AlertDescription>
            Start it with <code className="font-mono">grenz run</code>, or set{" "}
            <code className="font-mono">GRENZ_PROXY_URL</code> /{" "}
            <code className="font-mono">GRENZ_ADMIN_TOKEN</code>.
          </AlertDescription>
        </Alert>
      )}

      <StatRow>
        <Stat
          label="Requests screened"
          value={formatCount(total)}
          footer={<span className="text-muted-foreground">over the last {windowHours}h</span>}
        />
        <Stat
          label="Allowed"
          value={formatCount(allowN)}
          footer={
            <>
              <span className="text-allow-foreground font-medium">{pct(allowN)}%</span>
              <span className="text-muted-foreground">passed straight through</span>
            </>
          }
        />
        <Stat
          label="Denied"
          value={formatCount(denyN)}
          footer={
            <>
              <span className="text-deny-foreground font-medium">{pct(denyN)}%</span>
              <span className="text-muted-foreground">stopped at the door</span>
            </>
          }
        />
        <Stat
          label="Awaiting you"
          value={approvals.length}
          valueClassName={approvals.length > 0 ? "text-held-foreground" : undefined}
          suffix={approvals.length > 0 ? "held at the door" : undefined}
          footer={
            soonest !== null ? (
              <>
                <span className="text-held-foreground font-medium tabular-nums">
                  {countdown(soonest, nowTick)}
                </span>
                <span className="text-muted-foreground">until the oldest expires to deny</span>
              </>
            ) : (
              <span className="text-muted-foreground">nothing is blocked on a human</span>
            )
          }
        />
      </StatRow>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[2fr_1fr]">
        <Card className="gap-0 py-[18px]">
          <CardHeader className="px-5 pb-3.5">
            <CardTitle className="text-[14.5px]">Throughput</CardTitle>
            <CardDescription className="text-[12.5px]">
              Requests per hour, last {windowHours} hours, stacked by verdict.
            </CardDescription>
          </CardHeader>
          <CardContent className="px-5">
            <ThroughputChart requests={requests} windowHours={windowHours} now={nowTick} />
          </CardContent>
        </Card>

        <Card className="gap-0 py-[18px]">
          <CardHeader className="px-5 pb-0">
            <CardTitle className="text-[14.5px]">How it was decided</CardTitle>
            <CardDescription className="text-[12.5px]">Every verdict the engine reached.</CardDescription>
          </CardHeader>
          <CardContent className="px-5">
            <DecisionMix summary={summary} />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-[2fr_1fr]">
        <Card className="min-w-0 gap-0 overflow-hidden py-0">
          <CardHeader className="px-5 py-4">
            <CardTitle className="text-[14.5px]">Recent requests</CardTitle>
            <CardDescription className="text-[12.5px]">The last decisions, newest first.</CardDescription>
            <CardAction>
              <Link
                href="/requests"
                className="text-primary flex items-center gap-1.5 text-[12.5px] font-medium"
              >
                View all <ArrowRight className="size-3.5" />
              </Link>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            <RequestsTable
              rows={requests.slice(0, RECENT_ROWS)}
              now={nowTick}
              emptyMessage="No requests yet — this fills as your agents work."
            />
          </CardContent>
        </Card>

        <div className="flex min-w-0 flex-col gap-4">
          <Card className="border-held/30 gap-0 overflow-hidden py-0">
            <CardHeader className="px-[18px] py-3.5">
              <CardTitle className="flex items-center gap-2 text-[14.5px]">
                Awaiting you
                {approvals.length > 0 && (
                  <span className="bg-held/15 text-held-foreground inline-flex h-[18px] min-w-[18px] items-center justify-center rounded-full px-1.5 text-[11px] font-semibold">
                    {approvals.length}
                  </span>
                )}
              </CardTitle>
              <CardDescription className="text-[12.5px]">
                Held at the door. No answer in 5 minutes is a denial.
              </CardDescription>
            </CardHeader>
            <CardContent className="border-t px-0">
              <AwaitingYou limit={3} />
            </CardContent>
          </Card>

          <Card className="flex min-w-0 flex-1 flex-col gap-0 overflow-hidden py-0">
            <CardHeader className="px-[18px] py-3.5">
              <CardTitle className="text-[14.5px]">Firewall activity</CardTitle>
              <CardDescription className="text-[12.5px]">Defenses that fired.</CardDescription>
              <CardAction>
                <Link
                  href="/firewall"
                  className="text-primary flex items-center gap-1 text-[12.5px] font-medium"
                >
                  All <ArrowUpRight className="size-3.5" />
                </Link>
              </CardAction>
            </CardHeader>
            <CardContent className="flex flex-1 flex-col border-t px-0">
              <FirewallActivity limit={4} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
