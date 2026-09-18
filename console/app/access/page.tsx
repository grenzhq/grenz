"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertTriangle, Check, Copy, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/page-header";
import { useModal } from "@/components/use-modal";
import { cn } from "@/lib/utils";

type Origin = "auto" | "manual";

interface AgentRow {
  id: string;
  revoked: boolean;
  local: boolean;
  fleet: boolean;
  reason?: string;
  ts?: number;
  origin?: Origin;
}
interface OtherRow {
  id: string;
  reason: string;
  ts: number;
  origin: Origin;
}
interface View {
  enabled: boolean;
  agents: AgentRow[];
  other: OtherRow[];
}
interface GrantRow {
  id: string;
  agent: string;
  actions: string[];
  reason: string;
  created_at: number;
  expires_at: number;
  revoked: boolean;
}
type Msg = { kind: "ok" | "err" | "warn"; text: string };

const POLL_MS = 2000;
const MINT = "__mint__"; // busy sentinel for the grant form

const TTL_PRESETS: Array<{ label: string; secs: number }> = [
  { label: "5 min", secs: 300 },
  { label: "15 min", secs: 900 },
  { label: "30 min", secs: 1800 },
  { label: "1 hour", secs: 3600 },
];

function ago(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
function fmtDur(secs: number): string {
  if (secs <= 0) return "expired";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function AccessPage() {
  const [view, setView] = useState<View | null>(null);
  const [grants, setGrants] = useState<GrantRow[]>([]);
  const [offline, setOffline] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<Msg | null>(null);
  const busyRef = useRef<string | null>(null);
  busyRef.current = busy;
  const { confirm, prompt, node: modalNode } = useModal();

  // Grant-form state.
  const [gAgent, setGAgent] = useState("");
  const [gActions, setGActions] = useState("");
  const [gTtl, setGTtl] = useState(900);
  const [gReason, setGReason] = useState("");

  // Add-agent state. `minted` holds the one-time token reveal (in memory only —
  // never persisted; cleared when the reveal closes).
  const [addingAgent, setAddingAgent] = useState(false);
  const [newAgentId, setNewAgentId] = useState("");
  const [minting, setMinting] = useState(false);
  const [minted, setMinted] = useState<{ id: string; token: string } | null>(null);
  const [copied, setCopied] = useState(false);

  // A 1s local clock so grant countdowns tick smoothly, independent of the poll.
  const [nowTick, setNowTick] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const load = useCallback(async () => {
    try {
      // Revoking a grant mutates BOTH lists, so fetch them together — a
      // one-sided refetch would leave the page self-inconsistent for a tick.
      const [rRes, gRes] = await Promise.all([
        fetch("/api/revocations", { cache: "no-store" }),
        fetch("/api/grants", { cache: "no-store" }),
      ]);
      if (!rRes.ok) throw new Error(`http ${rRes.status}`);
      setView((await rRes.json()) as View);
      if (gRes.ok) setGrants(((await gRes.json()) as { grants: GrantRow[] }).grants ?? []);
      setOffline(false);
    } catch {
      setOffline(true);
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => {
      if (!busyRef.current) void load();
    }, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  // Revocation-endpoint actions (revoke agent, restore, end a grant early).
  const mutate = useCallback(
    async (id: string, init: RequestInit, describe: (body: Record<string, unknown>) => Msg) => {
      setBusy(id);
      setMsg(null);
      try {
        const res = await fetch(`/api/revocations/${encodeURIComponent(id)}`, {
          ...init,
          headers: { "content-type": "application/json", ...(init.headers ?? {}) },
        });
        const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
        if (res.ok) {
          setMsg(describe(body));
        } else if (res.status === 403) {
          setMsg({ kind: "err", text: "Forbidden — revoke/restore needs an admin token." });
        } else if (res.status === 409 && body.error === "revocations_disabled") {
          setMsg({ kind: "err", text: "The kill switch isn't enabled on this proxy." });
        } else {
          setMsg({ kind: "err", text: (body.error as string) ?? `Failed (${res.status}).` });
        }
      } catch {
        setMsg({ kind: "err", text: "Couldn't reach the proxy." });
      } finally {
        setBusy(null);
        await load();
      }
    },
    [load],
  );

  const revoke = async (id: string) => {
    const reason = await prompt({
      title: `Revoke ${id}`,
      body: "Cut off every request from this agent — an emergency kill-switch that takes effect before any credential is touched.",
      fieldLabel: "Reason (kept for operators, never a credential)",
      placeholder: "manual",
      defaultValue: "manual",
      confirmLabel: "Revoke",
      tone: "danger",
    });
    if (reason === null) return; // Cancel aborts — never a default revoke.
    const r = reason.trim() || "manual";
    void mutate(id, { method: "POST", body: JSON.stringify({ reason: r }) }, () => ({
      kind: "ok",
      text: `${id} is cut off.`,
    }));
  };

  const restore = async (id: string, reason?: string) => {
    const ok = await confirm({
      title: `Restore ${id}`,
      body: (
        <>
          This agent was cut off: <b>{reason ?? "manual"}</b>. Restore its access?
        </>
      ),
      confirmLabel: "Restore",
    });
    if (!ok) return;
    void mutate(id, { method: "DELETE" }, (body) => {
      if (body.fleet_revoked === true) {
        return { kind: "warn", text: `Local revocation lifted, but ${id} is still cut off by the signed fleet set — restore it at the source.` };
      }
      if (body.removed === false) return { kind: "warn", text: `${id} was already restored.` };
      return { kind: "ok", text: `${id} restored.` };
    });
  };

  const revokeGrant = async (id: string, agent: string, actions: string[]) => {
    const ok = await confirm({
      title: "End grant early?",
      body: (
        <>
          {agent} loses <span className="font-mono">[{actions.join(", ")}]</span> immediately.
        </>
      ),
      confirmLabel: "End grant",
      tone: "danger",
    });
    if (!ok) return;
    void mutate(id, { method: "POST", body: JSON.stringify({ reason: "grant ended from console" }) }, () => ({
      kind: "ok",
      text: `Grant ${id} ended.`,
    }));
  };

  const doMint = async (agent: string, actionsCsv: string, ttl: number, reason: string, requestedSecs: number) => {
    setBusy(MINT);
    setMsg(null);
    try {
      const res = await fetch("/api/grants", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agent, actions: actionsCsv, ttl, reason }),
      });
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (res.ok) {
        const exp = typeof body.expires_at === "number" ? body.expires_at : 0;
        const actualSecs = Math.max(0, Math.round((exp - Date.now()) / 1000));
        // Never echo the requested TTL — the proxy clamps silently. Report the
        // real granted duration from the response, and flag any clamp.
        const clamped = Math.abs(actualSecs - requestedSecs) > 30 ? ` (clamped to ${fmtDur(actualSecs)})` : "";
        setMsg({ kind: "ok", text: `Granted ${agent} [${actionsCsv}] — expires in ${fmtDur(actualSecs)}${clamped}.` });
        setGActions("");
        setGReason("");
      } else if (res.status === 403) {
        setMsg({ kind: "err", text: "Forbidden — granting needs an admin token." });
      } else if (res.status === 409 && body.error === "grants_disabled") {
        setMsg({ kind: "err", text: "Temporary grants aren't enabled on this proxy." });
      } else if (res.status === 429) {
        setMsg({ kind: "err", text: "Too many active grants — revoke some first." });
      } else if (res.status === 404) {
        setMsg({ kind: "err", text: `Unknown agent "${agent}".` });
      } else {
        setMsg({ kind: "err", text: (body.error as string) ?? `Failed (${res.status}).` });
      }
    } catch {
      setMsg({ kind: "err", text: "Couldn't reach the proxy." });
    } finally {
      setBusy(null);
      await load();
    }
  };

  const grant = async () => {
    const agent = gAgent.trim();
    const actionList = gActions.split(",").map((s) => s.trim()).filter(Boolean);
    if (!agent || actionList.length === 0 || !gReason.trim()) return;
    const ttlLabel = TTL_PRESETS.find((p) => p.secs === gTtl)?.label ?? `${gTtl}s`;
    const isRevoked = view?.agents.find((a) => a.id === agent)?.revoked ?? false;
    const facts = (
      <>
        Widen <b>{agent}</b> beyond its policy: <span className="font-mono">[{actionList.join(", ")}]</span> for{" "}
        <b>{ttlLabel}</b>. Matching actions skip approval prompts for the whole window; explicit denies still apply.
        {isRevoked && (
          <>
            {" "}
            <br />
            <span className="text-deny-foreground font-medium">
              {agent} is currently revoked — this grant has no effect until it is restored.
            </span>
          </>
        )}
      </>
    );
    // A bare * / *:* matches every action — the dangerous misclick. Escalate to
    // a typed confirmation instead of a one-click OK.
    const wildcard = actionList.some((a) => a === "*" || a === "*:*");
    if (wildcard) {
      const typed = await prompt({
        title: "Grant every action?",
        body: (
          <>
            {facts}
            <br />
            <span className="text-deny-foreground font-medium">⚠ This grant matches EVERY action not explicitly denied.</span>
          </>
        ),
        fieldLabel: `Type the agent id "${agent}" to confirm`,
        placeholder: agent,
        requireMatch: agent,
        confirmLabel: "Grant anyway",
        tone: "danger",
      });
      if (typed === null || typed.trim() !== agent) {
        setMsg({ kind: "warn", text: "Grant cancelled." });
        return;
      }
    } else if (!(await confirm({ title: "Grant temporary access?", body: facts, confirmLabel: "Grant" }))) {
      return;
    }
    void doMint(agent, actionList.join(","), gTtl, gReason.trim(), gTtl);
  };

  const createAgent = async () => {
    const id = newAgentId.trim();
    if (!id) return;
    setMinting(true);
    setMsg(null);
    try {
      const res = await fetch("/api/agents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const body = (await res.json().catch(() => ({}))) as { id?: string; token?: string; error?: string };
      if (res.ok && body.token) {
        setMinted({ id: body.id ?? id, token: body.token });
        setCopied(false);
        setNewAgentId("");
        setAddingAgent(false);
        await load(); // the new agent shows up in the list + grant picker
      } else if (res.status === 401 || res.status === 403) {
        setMsg({ kind: "err", text: "Forbidden — creating an agent needs an admin token." });
      } else if (res.status === 409 && body.error === "agent_exists") {
        setMsg({ kind: "err", text: `An agent named "${id}" already exists.` });
      } else if (res.status === 409 && body.error === "agents_admin_disabled") {
        setMsg({ kind: "err", text: "Agent creation isn’t enabled on this proxy." });
      } else if (res.status === 409 && body.error === "config_changed") {
        setMsg({ kind: "err", text: "grenz.yaml changed on disk — try again." });
      } else if (res.status === 400) {
        setMsg({ kind: "err", text: "Use a lowercase slug: letters, digits, - or _ (start with a letter or digit)." });
      } else if (res.status === 404) {
        setMsg({ kind: "err", text: "This proxy build doesn’t support adding agents yet — update Grenz and restart it." });
      } else {
        setMsg({ kind: "err", text: body.error ?? `Failed (${res.status}).` });
      }
    } catch {
      setMsg({ kind: "err", text: "Couldn’t reach the proxy." });
    } finally {
      setMinting(false);
    }
  };

  const copyToken = async () => {
    if (!minted) return;
    try {
      await navigator.clipboard.writeText(minted.token);
      setCopied(true);
    } catch {
      setMsg({ kind: "warn", text: "Couldn’t copy automatically — select the token and copy it." });
    }
  };

  function Pill({ a }: { a: AgentRow }) {
    const base =
      "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-[11px] font-medium";
    if (a.fleet)
      return <span className={cn(base, "border-deny/30 bg-deny/10 text-deny-foreground")}>Fleet-revoked</span>;
    if (a.revoked)
      return <span className={cn(base, "border-deny/30 bg-deny/10 text-deny-foreground")}>Revoked</span>;
    return <span className={cn(base, "border-allow/30 bg-allow/10 text-allow-foreground")}>Active</span>;
  }

  const grantIds = new Set(grants.map((g) => g.id));
  // A grant revoked early is also a non-agent revocation; suppress its duplicate
  // in `other` (its Restore there would silently re-arm the still-live grant —
  // the revoked tag in the grants list is the canonical surface).
  const otherRows = (view?.other ?? []).filter((o) => !grantIds.has(o.id));

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Access control">
        Act on an agent right now, without touching the policy. <b>Revoke</b> cuts one off instantly
        — an emergency kill-switch that takes effect before any credential is touched.{" "}
        <b>Grant</b> widens an agent past its policy for a bounded window that expires on its own.
      </PageHeader>

      {offline && (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertTitle>Can&rsquo;t reach the Grenz proxy.</AlertTitle>
          <AlertDescription>
            Start it with <code className="font-mono">grenz run</code>.
          </AlertDescription>
        </Alert>
      )}

      {view && !view.enabled && (
        <Alert>
          <AlertTitle>The kill switch isn&rsquo;t enabled on this proxy.</AlertTitle>
          <AlertDescription>
            No revocation store is configured, so access can&rsquo;t be revoked from here.
          </AlertDescription>
        </Alert>
      )}

      {msg && (
        <div
          className={cn(
            "rounded-lg border px-3.5 py-2.5 text-[12.5px]",
            msg.kind === "ok" && "border-allow/30 bg-allow/10 text-allow-foreground",
            msg.kind === "err" && "border-deny/30 bg-deny/10 text-deny-foreground",
            msg.kind === "warn" && "border-held/30 bg-held/10 text-held-foreground",
          )}
        >
          {msg.text}
        </div>
      )}

      {view?.enabled && (
        <>
          <Card className="min-w-0 gap-0 overflow-hidden py-0">
            <CardHeader className="items-center border-b px-[18px] py-3.5">
              <CardTitle className="text-[14.5px]">Agents</CardTitle>
              <CardAction>
                <Button variant="outline" size="sm" className="h-[30px]" onClick={() => setAddingAgent((v) => !v)}>
                  {addingAgent ? <X className="size-3.5" /> : <Plus className="size-3.5" />}
                  {addingAgent ? "Cancel" : "Add agent"}
                </Button>
              </CardAction>
            </CardHeader>

            {addingAgent && (
              <div className="bg-card-inset flex flex-col gap-2 border-b px-[18px] py-3.5">
                <div className="flex flex-wrap gap-2">
                  <Input
                    aria-label="New agent id"
                    placeholder="agent id, e.g. ci-bot"
                    value={newAgentId}
                    autoFocus
                    onChange={(e) => setNewAgentId(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && void createAgent()}
                    className="h-[30px] max-w-[260px] flex-1 font-mono text-[12.5px]"
                  />
                  <Button
                    size="sm"
                    className="h-[30px]"
                    disabled={minting || !newAgentId.trim()}
                    onClick={() => void createAgent()}
                  >
                    {minting ? "…" : "Create agent"}
                  </Button>
                </div>
                <p className="text-muted-foreground text-[12px]">
                  Mints a fresh <code className="font-mono">GRENZ_TOKEN</code>, adds the agent to{" "}
                  <code className="font-mono">grenz.yaml</code>, and makes it live now — no restart. The
                  token is shown once.
                </p>
              </div>
            )}

            <CardContent className="px-0">
              {view.agents.length === 0 ? (
                <div className="text-muted-foreground px-5 py-8 text-center text-[13px]">
                  No agents configured.
                </div>
              ) : (
                view.agents.map((a) => (
                  <div
                    key={a.id}
                    className="border-border-soft flex items-center gap-3 border-b px-[18px] py-3 last:border-b-0"
                  >
                    <span className="shrink-0 font-mono text-[12.5px] font-medium">{a.id}</span>
                    <Pill a={a} />
                    {a.local && a.reason && (
                      <span className="text-muted-foreground min-w-0 flex-1 truncate text-[12px]">
                        {a.origin === "auto" && (
                          <span className="border-deny/30 bg-deny/10 text-deny-foreground mr-1.5 rounded-full border px-1.5 py-0.5 text-[10.5px]">
                            auto
                          </span>
                        )}
                        {a.reason}
                        {a.ts ? ` · ${ago(a.ts)}` : ""}
                      </span>
                    )}
                    {a.fleet && !a.local && (
                      <span className="text-muted-foreground min-w-0 flex-1 truncate text-[12px]">
                        held by the signed fleet set
                      </span>
                    )}
                    <div className="ml-auto flex shrink-0 gap-2">
                      {!a.revoked && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-deny/30 text-deny-foreground hover:bg-deny/10 hover:text-deny-foreground h-[28px]"
                          disabled={busy === a.id}
                          onClick={() => void revoke(a.id)}
                        >
                          Revoke
                        </Button>
                      )}
                      {a.local && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-[28px]"
                          disabled={busy === a.id}
                          onClick={() => void restore(a.id, a.reason)}
                        >
                          Restore
                        </Button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card className="min-w-0 gap-0 overflow-hidden py-0">
            <CardHeader className="border-b px-[18px] py-3.5">
              <CardTitle className="text-[14.5px]">Temporary grants</CardTitle>
            </CardHeader>

            <div className="bg-card-inset flex flex-col gap-2 border-b px-[18px] py-3.5">
              <div className="flex flex-wrap items-center gap-2">
                <Select value={gAgent} onValueChange={setGAgent}>
                  <SelectTrigger size="sm" className="h-[30px] w-[160px]" aria-label="Agent">
                    <SelectValue placeholder="Agent…" />
                  </SelectTrigger>
                  <SelectContent>
                    {view.agents.map((a) => (
                      <SelectItem key={a.id} value={a.id}>
                        {a.id}
                        {a.revoked ? " · revoked" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  aria-label="Actions"
                  placeholder="actions, e.g. pr:merge, repo:delete"
                  value={gActions}
                  onChange={(e) => setGActions(e.target.value)}
                  className="h-[30px] min-w-[220px] flex-1 font-mono text-[12.5px]"
                />
                <Select value={String(gTtl)} onValueChange={(v) => setGTtl(Number(v))}>
                  <SelectTrigger size="sm" className="h-[30px] w-[130px]" aria-label="Duration">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TTL_PRESETS.map((p) => (
                      <SelectItem key={p.secs} value={String(p.secs)}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  aria-label="Reason"
                  placeholder="reason (required)"
                  value={gReason}
                  onChange={(e) => setGReason(e.target.value)}
                  className="h-[30px] min-w-[180px] flex-1 text-[12.5px]"
                />
                <Button
                  size="sm"
                  className="h-[30px]"
                  disabled={busy === MINT || !gAgent || !gActions.trim() || !gReason.trim()}
                  onClick={() => void grant()}
                >
                  {busy === MINT ? "…" : "Grant"}
                </Button>
              </div>
              <p className="text-muted-foreground text-[12px]">
                Grants fill policy gaps and skip approval prompts for the window — they never override
                an explicit deny.
                {view.agents.length <= 1 && (
                  <>
                    {" "}
                    The agent list comes from your <code className="font-mono">grenz.yaml</code> — add
                    more agents there to widen it.
                  </>
                )}
              </p>
            </div>

            <CardContent className="px-0">
              {grants.length === 0 ? (
                <div className="text-muted-foreground px-5 py-8 text-center text-[13px]">
                  No temporary grants.
                </div>
              ) : (
                grants.map((g) => {
                  const remaining = Math.max(0, Math.round((g.expires_at - nowTick) / 1000));
                  return (
                    <div
                      key={g.id}
                      className="border-border-soft flex items-center gap-3 border-b px-[18px] py-3 last:border-b-0"
                    >
                      <span className="shrink-0 font-mono text-[12.5px] font-medium">{g.id}</span>
                      <span className="text-muted-foreground min-w-0 flex-1 truncate text-[12px]">
                        {g.agent} · [{g.actions.join(", ")}]
                        {g.revoked ? (
                          <>
                            {" · "}
                            <span className="border-deny/30 bg-deny/10 text-deny-foreground rounded-full border px-1.5 py-0.5 text-[10.5px]">
                              revoked
                            </span>
                          </>
                        ) : (
                          ` · ${fmtDur(remaining)} left`
                        )}
                        {g.reason ? ` · ${g.reason}` : ""}
                      </span>
                      {!g.revoked && remaining > 0 && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-deny/30 text-deny-foreground hover:bg-deny/10 hover:text-deny-foreground ml-auto h-[28px] shrink-0"
                          disabled={busy === g.id}
                          onClick={() => void revokeGrant(g.id, g.agent, g.actions)}
                        >
                          Revoke
                        </Button>
                      )}
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>

          <Card className="min-w-0 gap-0 overflow-hidden py-0">
            <CardHeader className="border-b px-[18px] py-3.5">
              <CardTitle className="text-[14.5px]">Session &amp; delegation revocations</CardTitle>
            </CardHeader>
            <CardContent className="px-0">
              {otherRows.length === 0 ? (
                <div className="text-muted-foreground px-5 py-8 text-center text-[13px]">None.</div>
              ) : (
                otherRows.map((o) => (
                  <div
                    key={o.id}
                    className="border-border-soft flex items-center gap-3 border-b px-[18px] py-3 last:border-b-0"
                  >
                    <span className="shrink-0 font-mono text-[12.5px] font-medium">{o.id}</span>
                    <span
                      className={cn(
                        "shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium",
                        o.origin === "auto"
                          ? "border-deny/30 bg-deny/10 text-deny-foreground"
                          : "bg-muted text-muted-foreground",
                      )}
                      title={o.origin === "auto" ? undefined : "not a configured agent"}
                    >
                      {o.origin === "auto" ? "auto" : "stale id"}
                    </span>
                    <span className="text-muted-foreground min-w-0 flex-1 truncate text-[12px]">
                      {o.reason} · {ago(o.ts)}
                    </span>
                    <Button
                      size="sm"
                      variant="outline"
                      className="ml-auto h-[28px] shrink-0"
                      disabled={busy === o.id}
                      onClick={() => void restore(o.id, o.reason)}
                    >
                      Restore
                    </Button>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <p className="text-muted-foreground text-[12.5px]">
            Revoking denies every request from an agent at the door — before any credential is touched
            — and takes effect immediately, no restart. A temporary grant widens an agent past its
            policy for a bounded window, then expires on its own.
          </p>
        </>
      )}
      {modalNode}

      {/* Deliberately not dismissable by scrim or Esc — the token is shown once,
          so closing is an explicit "Done" rather than something you can do by
          accident before copying it. */}
      <Dialog open={minted !== null}>
        <DialogContent
          showCloseButton={false}
          onEscapeKeyDown={(e) => e.preventDefault()}
          onInteractOutside={(e) => e.preventDefault()}
          className="sm:max-w-[520px]"
        >
          <DialogHeader>
            <DialogTitle>Agent &ldquo;{minted?.id}&rdquo; created</DialogTitle>
            <DialogDescription>
              Copy its token now — it is <b>shown once</b> and cannot be retrieved again. Set it as{" "}
              <code className="font-mono">GRENZ_TOKEN</code> in {minted?.id}&rsquo;s environment.
            </DialogDescription>
          </DialogHeader>
          <div className="bg-card-inset flex items-center gap-2 rounded-lg border p-2">
            <code className="min-w-0 flex-1 font-mono text-[12px] break-all">{minted?.token}</code>
            <Button size="sm" variant="outline" className="shrink-0" onClick={() => void copyToken()}>
              {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <DialogFooter>
            <Button onClick={() => setMinted(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
