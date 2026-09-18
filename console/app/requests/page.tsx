"use client";

import { useMemo, useState } from "react";
import { Search, X } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useConsole } from "@/components/console-data";
import { RequestsTable } from "@/components/requests-table";
import { RequestDetail } from "@/components/request-detail";
import type { RequestRow } from "@/lib/types";

export default function RequestsPage() {
  const { requests, nowTick } = useConsole();
  const [selected, setSelected] = useState<RequestRow | null>(null);
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("all");
  const [agent, setAgent] = useState("all");

  const agentsSeen = useMemo(
    () => Array.from(new Set(requests.map((r) => r.agentId).filter(Boolean))),
    [requests],
  );

  const filtered = useMemo(
    () =>
      requests.filter((r) => {
        if (decision !== "all" && r.decision !== decision) return false;
        if (agent !== "all" && r.agentId !== agent) return false;
        const q = query.trim().toLowerCase();
        if (q) {
          const hay =
            `${r.tool}:${r.action} ${r.target ?? ""} ${r.agentId ?? ""} ${r.reason ?? ""}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      }),
    [requests, query, decision, agent],
  );

  const filtersActive = decision !== "all" || agent !== "all" || query.trim() !== "";

  // The log is the page: it owns the viewport and scrolls inside its own card,
  // so the filter bar and the detail panel stay put while you read down it.
  // 57px is the header height the shell puts above us.
  return (
    <div className="flex h-[calc(100svh-57px)] min-h-0 min-w-0 flex-1 flex-col gap-3.5 overflow-hidden p-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-[22px] font-semibold tracking-tight">Requests</h1>
        <p className="text-muted-foreground text-[13.5px]">
          {requests.length} decisions in the log. Pick a row to see what the policy said.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] flex-1">
          <Search className="text-muted-foreground pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search action, target, agent, reason…"
            aria-label="Search requests"
            className="h-[34px] pr-24 pl-9 font-mono text-[12.5px]"
          />
          {filtersActive && (
            <span className="text-muted-foreground pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 font-mono text-[11px]">
              {filtered.length} of {requests.length}
            </span>
          )}
        </div>

        <Select value={decision} onValueChange={setDecision}>
          <SelectTrigger size="sm" className="h-[34px] w-[150px]" aria-label="Filter by decision">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All decisions</SelectItem>
            <SelectItem value="allow">Allowed</SelectItem>
            <SelectItem value="deny">Denied</SelectItem>
            <SelectItem value="require_approval">Held</SelectItem>
          </SelectContent>
        </Select>

        <Select value={agent} onValueChange={setAgent}>
          <SelectTrigger size="sm" className="h-[34px] w-[150px]" aria-label="Filter by agent">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All agents</SelectItem>
            {agentsSeen.map((a) => (
              <SelectItem key={a} value={a}>
                {a}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {filtersActive && (
          <Button
            variant="ghost"
            size="sm"
            className="h-[34px]"
            onClick={() => {
              setQuery("");
              setDecision("all");
              setAgent("all");
            }}
          >
            <X className="size-3.5" />
            Clear
          </Button>
        )}
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
        <Card className="flex min-h-0 min-w-0 flex-col gap-0 overflow-hidden py-0">
          <div className="min-h-0 flex-1 overflow-auto">
            <RequestsTable
              rows={filtered}
              now={nowTick}
              selected={selected}
              onSelect={setSelected}
              showReason
              emptyMessage={
                filtersActive ? "No requests match these filters." : "No requests yet."
              }
            />
          </div>
        </Card>

        <Card className="hidden min-h-0 flex-col gap-0 overflow-hidden py-0 xl:flex">
          <RequestDetail req={selected} onClose={() => setSelected(null)} />
        </Card>
      </div>
    </div>
  );
}
