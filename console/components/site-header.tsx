"use client";

import { usePathname } from "next/navigation";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { ThemeToggle } from "@/components/theme-toggle";
import { useConsole } from "@/components/console-data";
import { cn } from "@/lib/utils";

const CRUMBS: Record<string, [string, string]> = {
  "/": ["Monitor", "Overview"],
  "/requests": ["Monitor", "Requests"],
  "/firewall": ["Monitor", "Firewall"],
  "/approvals": ["Control", "Approvals"],
  "/agents": ["Control", "Agents"],
  "/grants": ["Control", "Grants"],
  "/permissions": ["Configure", "Permissions"],
  "/setup": ["Configure", "Set up permissions"],
  "/policy": ["Configure", "Rules"],
  "/access": ["Configure", "Access"],
  "/budgets": ["Configure", "Budgets"],
};

export function SiteHeader() {
  const pathname = usePathname();
  const { online } = useConsole();
  const [group, page] = CRUMBS[pathname] ?? ["Monitor", "Console"];

  return (
    <header className="flex h-[57px] shrink-0 items-center gap-2.5 border-b px-6">
      <SidebarTrigger className="-ml-1.5" />
      <Separator orientation="vertical" className="!h-4" />
      <span className="text-muted-foreground text-[13.5px]">{group}</span>
      <span className="text-muted-foreground/50 text-[13.5px]">/</span>
      <span className="text-secondary-foreground text-[13.5px] font-medium">{page}</span>

      <div className="ml-auto flex items-center gap-2">
        <span
          className={cn(
            "inline-flex h-[30px] items-center gap-2 rounded-md border px-2.5 text-[12.5px] font-medium",
            online
              ? "border-primary/30 bg-primary/8 text-primary"
              : "border-deny/30 bg-deny/8 text-deny-foreground",
          )}
        >
          <span className={cn("size-1.5 rounded-full", online ? "bg-primary" : "bg-deny")} />
          {online ? "Live" : "Offline"}
        </span>
        <ThemeToggle />
      </div>
    </header>
  );
}
