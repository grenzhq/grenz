"use client";

import { Card, CardContent } from "@/components/ui/card";
import { useConsole } from "@/components/console-data";
import { EmptyNote, PageHeader } from "@/components/page-header";
import { secondsLeft } from "@/lib/format";

export default function GrantsPage() {
  const { grants, nowTick } = useConsole();

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Grants">
        Standing permissions handed out beyond the policy file. Every one carries an expiry, so the
        set shrinks by itself if nobody renews it.
      </PageHeader>

      <Card className="min-w-0 gap-0 overflow-hidden py-0">
        <CardContent className="px-0">
          {grants.length === 0 ? (
            <EmptyNote>No active grants — the policy file is the only thing allowing anything.</EmptyNote>
          ) : (
            grants.map((g) => (
              <div
                key={g.id}
                className="border-border-soft flex flex-col gap-1.5 border-b px-[18px] py-3.5 last:border-b-0"
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-[12.5px] font-medium">{g.id}</span>
                  <span className="text-muted-foreground text-[12.5px]">{g.agent}</span>
                  {g.revoked && (
                    <span className="border-deny/30 bg-deny/10 text-deny-foreground rounded-full border px-2 py-0.5 text-[11px] font-medium">
                      revoked
                    </span>
                  )}
                  <span className="text-muted-foreground ml-auto shrink-0 font-mono text-[11.5px]">
                    expires in {secondsLeft(g.expires_at, nowTick)}s
                  </span>
                </div>
                <div className="text-muted-foreground truncate font-mono text-[11.5px]">
                  [{g.actions.join(", ")}]{g.reason ? ` · ${g.reason}` : ""}
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
