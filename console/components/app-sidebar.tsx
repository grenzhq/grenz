"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  CreditCard,
  FileText,
  ShieldCheck,
  Inbox,
  KeyRound,
  LayoutGrid,
  List,
  Lock,
  Shield,
  Users,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { useConsole } from "@/components/console-data";
import { cn } from "@/lib/utils";

interface NavItem {
  title: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  /** Pages that exist only as sections of another page for now. */
  disabled?: boolean;
}

const GROUPS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Monitor",
    items: [
      { title: "Overview", href: "/", icon: LayoutGrid },
      { title: "Requests", href: "/requests", icon: List },
      { title: "Firewall", href: "/firewall", icon: Shield },
    ],
  },
  {
    label: "Control",
    items: [
      { title: "Approvals", href: "/approvals", icon: Inbox },
      { title: "Agents", href: "/agents", icon: Users },
      { title: "Grants", href: "/grants", icon: KeyRound },
    ],
  },
  {
    label: "Configure",
    items: [
      { title: "Permissions", href: "/permissions", icon: ShieldCheck },
      { title: "Rules", href: "/policy", icon: FileText },
      { title: "Access", href: "/access", icon: Lock },
      { title: "Budgets", href: "/budgets", icon: CreditCard },
    ],
  },
];

export function AppSidebar() {
  const pathname = usePathname();
  const { approvals, online } = useConsole();

  return (
    <Sidebar collapsible="icon" className="border-r">
      <SidebarHeader className="h-[57px] justify-center border-b px-4">
        <Link href="/" className="flex items-center gap-2.5 overflow-hidden">
          <span className="bg-primary text-primary-foreground flex size-6 shrink-0 items-center justify-center rounded-md">
            <Shield className="size-3.5" />
          </span>
          <span className="truncate text-[15px] font-semibold tracking-tight">grenz</span>
          <span className="text-muted-foreground ml-auto font-mono text-[11px]">0.3.0</span>
        </Link>
      </SidebarHeader>

      <SidebarContent className="gap-5 px-1 py-4">
        {GROUPS.map((group) => (
          <SidebarGroup key={group.label} className="py-0">
            <SidebarGroupLabel className="text-muted-foreground h-auto pb-1.5 text-xs font-medium">
              {group.label}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => {
                  const active = pathname === item.href;
                  const pending = item.href === "/approvals" ? approvals.length : 0;
                  return (
                    <SidebarMenuItem key={item.href}>
                      <SidebarMenuButton asChild isActive={active} tooltip={item.title}>
                        <Link href={item.href}>
                          <item.icon className="size-4" />
                          <span>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                      {pending > 0 && (
                        <SidebarMenuBadge className="border-held/30 bg-held/15 text-held-foreground rounded-full border text-[11px] font-semibold">
                          {pending}
                        </SidebarMenuBadge>
                      )}
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter className="border-t px-4 py-3 group-data-[collapsible=icon]:hidden">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "size-1.5 shrink-0 rounded-full",
              online ? "bg-primary" : "bg-deny",
            )}
          />
          <span className="text-secondary-foreground truncate text-[12.5px] font-medium">
            {online ? "Proxy connected" : "Proxy unreachable"}
          </span>
        </div>
        <div className="text-muted-foreground truncate font-mono text-[11px]">
          127.0.0.1 · admin API
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
