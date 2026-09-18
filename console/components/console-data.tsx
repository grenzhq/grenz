"use client";

/**
 * One poller for the whole console.
 *
 * Every screen reads the same admin snapshot — the sidebar wants the pending
 * count, Overview wants all of it, Requests wants the log — so polling once at
 * the shell and sharing it through context keeps the proxy hit at one round of
 * requests per interval no matter how many panels are mounted.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type {
  AgentBudget,
  AgentRisk,
  Approval,
  BlastRadius,
  FirewallEvent,
  Grant,
  RequestRow,
  Summary,
} from "@/lib/types";

const POLL_MS = 5000;

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`http ${res.status}`);
  return (await res.json()) as T;
}

interface ConsoleData {
  summary: Summary | null;
  requests: RequestRow[];
  approvals: Approval[];
  blast: BlastRadius | null;
  budgets: AgentBudget[];
  risk: AgentRisk[];
  grants: Grant[];
  firewall: FirewallEvent[];
  freshIds: Set<number>;
  online: boolean;
  busy: string | null;
  nowTick: number;
  decide: (id: string, action: "approve" | "deny") => Promise<void>;
  refresh: () => Promise<void>;
}

const Ctx = createContext<ConsoleData | null>(null);

export function useConsole(): ConsoleData {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useConsole must be used inside <ConsoleDataProvider>");
  return ctx;
}

export function ConsoleDataProvider({ children }: { children: ReactNode }) {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [requests, setRequests] = useState<RequestRow[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [blast, setBlast] = useState<BlastRadius | null>(null);
  const [budgets, setBudgets] = useState<AgentBudget[]>([]);
  const [risk, setRisk] = useState<AgentRisk[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [firewall, setFirewall] = useState<FirewallEvent[]>([]);
  const [freshIds, setFreshIds] = useState<Set<number>>(new Set());
  const [online, setOnline] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [nowTick, setNowTick] = useState(() => Date.now());
  // Highest firewall-event id seen so far, so a new arrival can pulse once.
  const seenMaxId = useRef(0);

  const poll = useCallback(async () => {
    try {
      const [s, r, a, b, bu, ri, g, fw] = await Promise.all([
        getJson<Summary>("/api/summary"),
        getJson<{ requests: RequestRow[] }>("/api/requests"),
        getJson<{ approvals: Approval[] }>("/api/approvals"),
        getJson<BlastRadius>("/api/blast-radius"),
        getJson<{ agents: AgentBudget[] }>("/api/budgets"),
        getJson<{ agents: AgentRisk[] }>("/api/risk"),
        getJson<{ grants: Grant[] }>("/api/grants"),
        getJson<{ events: FirewallEvent[] }>("/api/firewall"),
      ]);
      setSummary(s);
      setRequests(r.requests ?? []);
      setApprovals(a.approvals ?? []);
      setBlast(b);
      setBudgets(bu.agents ?? []);
      setRisk(ri.agents ?? []);
      setGrants(g.grants ?? []);
      const events = fw.events ?? [];
      setFirewall(events);
      // Flag events newer than anything seen before — but never on first load,
      // so a page open doesn't pulse the whole backlog.
      const maxId = events.reduce((m, e) => Math.max(m, e.id), 0);
      if (seenMaxId.current > 0) {
        const fresh = events.filter((e) => e.id > seenMaxId.current).map((e) => e.id);
        if (fresh.length > 0) setFreshIds(new Set(fresh));
      }
      seenMaxId.current = Math.max(seenMaxId.current, maxId);
      setNowTick(Date.now());
      setOnline(true);
    } catch {
      setOnline(false);
    }
  }, []);

  useEffect(() => {
    // Poll only while the tab is visible. A backgrounded console has no viewer,
    // so hammering the proxy every few seconds is pure waste; pause on hide and
    // refresh immediately on return so the numbers are current when looked at.
    let timer: ReturnType<typeof setInterval> | undefined;
    const start = () => {
      if (timer !== undefined) return;
      void poll();
      timer = setInterval(() => void poll(), POLL_MS);
    };
    const stop = () => {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
    };
    const onVisibility = () => (document.visibilityState === "visible" ? start() : stop());
    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      stop();
    };
  }, [poll]);

  // Let the "new event" pulse play once, then drop the flag.
  useEffect(() => {
    if (freshIds.size === 0) return;
    const t = setTimeout(() => setFreshIds(new Set()), 1600);
    return () => clearTimeout(t);
  }, [freshIds]);

  const decide = useCallback(
    async (id: string, action: "approve" | "deny") => {
      setBusy(id);
      try {
        await fetch(`/api/approvals/${id}/${action}`, { method: "POST" });
        await poll();
      } finally {
        setBusy(null);
      }
    },
    [poll],
  );

  const value = useMemo<ConsoleData>(
    () => ({
      summary,
      requests,
      approvals,
      blast,
      budgets,
      risk,
      grants,
      firewall,
      freshIds,
      online,
      busy,
      nowTick,
      decide,
      refresh: poll,
    }),
    [summary, requests, approvals, blast, budgets, risk, grants, firewall, freshIds, online, busy, nowTick, decide, poll],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
