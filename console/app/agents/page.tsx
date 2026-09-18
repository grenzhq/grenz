"use client";

import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useConsole } from "@/components/console-data";
import { DecisionBadge } from "@/components/decision-badge";
import { EmptyNote, PageHeader } from "@/components/page-header";
import { severityTone } from "@/lib/format";

export default function AgentsPage() {
  const { risk, blast } = useConsole();
  const upstreams = blast?.upstreams ?? [];
  const delegations = blast?.delegations ?? [];

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Agents">
        Who is acting on your behalf, how far each one can reach, and what has been lent out.
        Revoking an agent lives on <Link href="/access" className="text-primary font-medium">Access</Link>.
      </PageHeader>

      <Card className="min-w-0 gap-0 overflow-hidden py-0">
        <CardHeader className="px-[18px] py-3.5">
          <CardTitle className="text-[14.5px]">Risk</CardTitle>
          <CardDescription className="text-[12.5px]">
            Scored from each agent&rsquo;s own traffic — denial rate, breadth, and what it reached for.
          </CardDescription>
        </CardHeader>
        <CardContent className="border-t px-0">
          {risk.length === 0 ? (
            <EmptyNote>No agent has made a request yet.</EmptyNote>
          ) : (
            risk.map((a) => (
              <div
                key={a.agent}
                className="border-border-soft flex items-center gap-3 border-b px-[18px] py-3 last:border-b-0"
              >
                <span className="shrink-0 font-mono text-[12.5px] font-medium">{a.agent}</span>
                <DecisionBadge decision={severityTone(a.level)}>
                  {a.level} · {a.score}
                </DecisionBadge>
                <span className="text-muted-foreground min-w-0 flex-1 truncate text-[12.5px]">
                  {a.reasons.join(" · ") || "no findings"}
                </span>
                <span className="text-muted-foreground shrink-0 font-mono text-[11.5px]">
                  {a.deny}/{a.total} denied
                </span>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      <Card className="min-w-0 gap-0 overflow-hidden py-0">
        <CardHeader className="px-[18px] py-3.5">
          <CardTitle className="text-[14.5px]">Blast radius</CardTitle>
          <CardDescription className="text-[12.5px]">
            What a grant actually reaches once the patterns are expanded.
          </CardDescription>
          {blast && (
            <CardAction>
              <DecisionBadge decision={severityTone(blast.severity)}>{blast.severity}</DecisionBadge>
            </CardAction>
          )}
        </CardHeader>
        <CardContent className="border-t px-0">
          {upstreams.length === 0 ? (
            <EmptyNote>No upstreams to analyze yet.</EmptyNote>
          ) : (
            <div className="grid grid-cols-1 gap-px md:grid-cols-2 lg:grid-cols-3">
              {upstreams.map((u) => (
                <div key={u.upstream} className="flex flex-col gap-2 px-[18px] py-3.5">
                  <div className="flex items-baseline gap-2">
                    <span className="truncate font-mono text-[12.5px] font-medium">{u.upstream}</span>
                    <span className="text-muted-foreground text-[11.5px]">{u.type}</span>
                  </div>
                  {u.enumerable ? (
                    <>
                      <div className="flex flex-wrap gap-1.5">
                        <DecisionBadge decision="allow">{u.autoAllow.length} auto-allow</DecisionBadge>
                        <DecisionBadge decision="require_approval">
                          {u.requiresApproval.length} approval
                        </DecisionBadge>
                      </div>
                      {u.broadGrants.map((bg) => (
                        <div
                          key={bg.pattern}
                          className="text-deny-foreground flex gap-2 text-[11.5px]"
                        >
                          <AlertTriangle className="mt-px size-3.5 shrink-0" />
                          <span className="min-w-0">
                            <span className="font-mono">{bg.pattern}</span> reaches{" "}
                            {bg.matches.join(", ")}
                          </span>
                        </div>
                      ))}
                    </>
                  ) : (
                    <span className="text-muted-foreground text-[11.5px]">
                      not enumerable — raw grant patterns only
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="min-w-0 gap-0 overflow-hidden py-0">
        <CardHeader className="px-[18px] py-3.5">
          <CardTitle className="text-[14.5px]">Live delegations</CardTitle>
          <CardDescription className="text-[12.5px]">
            Authority one agent has lent another, and when it lapses.
          </CardDescription>
        </CardHeader>
        <CardContent className="border-t px-0">
          {delegations.length === 0 ? (
            <EmptyNote>No active delegations.</EmptyNote>
          ) : (
            delegations.map((d) => (
              <div
                key={d.id}
                className="border-border-soft flex items-center gap-3 border-b px-[18px] py-3 last:border-b-0"
              >
                <span className="shrink-0 font-mono text-[12.5px]">{d.id}</span>
                <span className="text-muted-foreground min-w-0 flex-1 truncate font-mono text-[11.5px]">
                  [{d.actions.join(", ")}]{d.note ? ` · ${d.note}` : ""}
                </span>
                <span className="text-muted-foreground shrink-0 font-mono text-[11.5px]">
                  expires in {d.expiresInSeconds}s
                </span>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
