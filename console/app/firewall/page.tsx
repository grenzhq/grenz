"use client";

import { Card, CardContent } from "@/components/ui/card";
import { useConsole } from "@/components/console-data";
import { FirewallActivity } from "@/components/firewall-activity";
import { PageHeader } from "@/components/page-header";

export default function FirewallPage() {
  const { firewall } = useConsole();
  const shadow = firewall.filter((e) => e.shadow).length;

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Firewall">
        Each defense the proxy fires, and what tripped it.
        {shadow > 0 && ` ${shadow} logged in shadow mode — observed, not enforced.`}
      </PageHeader>

      <Card className="flex min-w-0 flex-col gap-0 overflow-hidden py-0">
        <CardContent className="flex flex-col px-0">
          <FirewallActivity />
        </CardContent>
      </Card>
    </div>
  );
}
