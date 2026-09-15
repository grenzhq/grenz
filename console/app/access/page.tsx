"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Nav, PageHead } from "../Nav";
import { Select, type SelectOption } from "../Select";
import { useModal } from "../Modal";

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
          {agent} loses <span className="mono">[{actions.join(", ")}]</span> immediately.
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
        Widen <b>{agent}</b> beyond its policy: <span className="mono">[{actionList.join(", ")}]</span> for{" "}
        <b>{ttlLabel}</b>. Matching actions skip approval prompts for the whole window; explicit denies still apply.
        {isRevoked && (
          <>
            {" "}
            <br />
            <span className="modal-warn">
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
            <span className="modal-warn">⚠ This grant matches EVERY action not explicitly denied.</span>
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
    if (a.fleet) return <span className="badge fleet">Fleet-revoked</span>;
    if (a.revoked) return <span className="badge revoked">Revoked</span>;
    return <span className="badge active">Active</span>;
  }

  const grantIds = new Set(grants.map((g) => g.id));
  // A grant revoked early is also a non-agent revocation; suppress its duplicate
  // in `other` (its Restore there would silently re-arm the still-live grant —
  // the revoked tag in the grants list is the canonical surface).
  const otherRows = (view?.other ?? []).filter((o) => !grantIds.has(o.id));

  return (
    <>
      <Nav />
      <div className="wrap">
        <PageHead title="Access control">
        Act on an agent right now, without touching the policy. <b>Revoke</b> cuts one off instantly — an emergency
        kill-switch that takes effect before any credential is touched. <b>Grant</b> widens an agent past its policy
        for a bounded window that expires on its own.
      </PageHead>

      {offline && (
        <div className="offline">
          Can’t reach the Grenz proxy. Start it with <code>grenz run</code>.
        </div>
      )}

      {view && !view.enabled && (
        <div className="offline info">
          The kill switch isn’t enabled on this proxy — no revocation store is configured. Access can’t be
          revoked from here.
        </div>
      )}

      {msg && <div className={`ks-msg ${msg.kind}`}>{msg.text}</div>}

      {view?.enabled && (
        <>
          <div className="sec-head">
            <h2>Agents</h2>
            <button className="add-agent-btn" onClick={() => setAddingAgent((v) => !v)}>
              {addingAgent ? "Cancel" : "+ Add agent"}
            </button>
          </div>

          {addingAgent && (
            <div className="card ks-card add-agent-form">
              <input
                aria-label="new agent id"
                placeholder="agent id, e.g. ci-bot"
                value={newAgentId}
                autoFocus
                onChange={(e) => setNewAgentId(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void createAgent()}
              />
              <button
                className="approve"
                disabled={minting || !newAgentId.trim()}
                onClick={() => void createAgent()}
              >
                {minting ? "…" : "Create agent"}
              </button>
              <div className="ks-caption add-agent-note">
                Mints a fresh <code>GRENZ_TOKEN</code>, adds the agent to <code>grenz.yaml</code>, and makes it live
                now — no restart. The token is shown once.
              </div>
            </div>
          )}

          <div className="card">
            {view.agents.length === 0 ? (
              <div className="empty">No agents configured.</div>
            ) : (
              view.agents.map((a) => (
                <div className="approval-row" key={a.id}>
                  <div className="meta">
                    <span className="ks-id">{a.id}</span>
                    <Pill a={a} />
                    {a.local && a.reason && (
                      <span className="ks-reason">
                        {a.origin === "auto" && <span className="badge deny">auto</span>} {a.reason}
                        {a.ts ? ` · ${ago(a.ts)}` : ""}
                      </span>
                    )}
                    {a.fleet && !a.local && <span className="ks-reason">held by the signed fleet set</span>}
                  </div>
                  <div className="btns">
                    {!a.revoked && (
                      <button className="deny" disabled={busy === a.id} onClick={() => void revoke(a.id)}>
                        Revoke
                      </button>
                    )}
                    {a.local && (
                      <button className="restore" disabled={busy === a.id} onClick={() => void restore(a.id, a.reason)}>
                        Restore
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>

          <h2>Temporary grants</h2>
          <div className="card ks-card">
            <div className="ks-form">
              <Select
                ariaLabel="agent"
                className="ks-agent"
                placeholder="Agent…"
                value={gAgent}
                onChange={setGAgent}
                options={view.agents.map<SelectOption>((a) => ({
                  value: a.id,
                  label: a.id,
                  hint: a.revoked ? "revoked" : undefined,
                }))}
              />
              <input
                aria-label="actions"
                placeholder="actions, e.g. pr:merge, repo:delete"
                value={gActions}
                onChange={(e) => setGActions(e.target.value)}
              />
              <Select
                ariaLabel="duration"
                className="ks-ttl"
                value={String(gTtl)}
                onChange={(v) => setGTtl(Number(v))}
                options={TTL_PRESETS.map<SelectOption>((p) => ({ value: String(p.secs), label: p.label }))}
              />
              <input
                aria-label="reason"
                placeholder="reason (required)"
                value={gReason}
                onChange={(e) => setGReason(e.target.value)}
              />
              <button
                className="approve"
                disabled={busy === MINT || !gAgent || !gActions.trim() || !gReason.trim()}
                onClick={() => void grant()}
              >
                {busy === MINT ? "…" : "Grant"}
              </button>
            </div>
            <div className="ks-caption">
              Grants fill policy gaps and skip approval prompts for the window — they never override an explicit
              deny.
              {view.agents.length <= 1 && (
                <>
                  {" "}
                  The agent list comes from your <code>grenz.yaml</code> — add more agents there to widen it.
                </>
              )}
            </div>
          </div>

          <div className="card">
            {grants.length === 0 ? (
              <div className="empty">No temporary grants.</div>
            ) : (
              grants.map((g) => {
                const remaining = Math.max(0, Math.round((g.expires_at - nowTick) / 1000));
                return (
                  <div className="approval-row" key={g.id}>
                    <div className="meta">
                      <span className="ks-id">{g.id}</span>
                      <span className="ks-reason">
                        {g.agent} · [{g.actions.join(", ")}]
                        {g.revoked ? (
                          <> · <span className="badge revoked">revoked</span></>
                        ) : (
                          ` · ${fmtDur(remaining)} left`
                        )}
                        {g.reason ? ` · ${g.reason}` : ""}
                      </span>
                    </div>
                    <div className="btns">
                      {!g.revoked && remaining > 0 && (
                        <button className="deny" disabled={busy === g.id} onClick={() => void revokeGrant(g.id, g.agent, g.actions)}>
                          Revoke
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <h2>Session &amp; delegation revocations</h2>
          <div className="card">
            {otherRows.length === 0 ? (
              <div className="empty">None.</div>
            ) : (
              otherRows.map((o) => (
                <div className="approval-row" key={o.id}>
                  <div className="meta">
                    <span className="ks-id">{o.id}</span>
                    {o.origin === "auto" ? (
                      <span className="badge deny">auto</span>
                    ) : (
                      <span className="badge fleet" title="not a configured agent">
                        stale id
                      </span>
                    )}
                    <span className="ks-reason">
                      {o.reason} · {ago(o.ts)}
                    </span>
                  </div>
                  <div className="btns">
                    <button className="restore" disabled={busy === o.id} onClick={() => void restore(o.id, o.reason)}>
                      Restore
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="pol-note">
            Revoking denies every request from an agent at the door — before any credential is touched — and
            takes effect immediately, no restart. A temporary grant widens an agent past its policy for a bounded
            window, then expires on its own.
          </div>
        </>
      )}
      {modalNode}

      {minted && (
        // Deliberately NOT dismissable by scrim click — the token is shown once,
        // so closing is an explicit "Done" to avoid losing it before copying.
        <div className="modal-scrim" role="presentation">
          <div className="modal token-reveal" role="alertdialog" aria-modal="true" aria-label={`Agent ${minted.id} created`}>
            <div className="modal-title">Agent “{minted.id}” created</div>
            <div className="modal-body">
              Copy its token now — it is <b>shown once</b> and cannot be retrieved again. Set it as{" "}
              <code>GRENZ_TOKEN</code> in {minted.id}’s environment.
            </div>
            <div className="token-box">
              <code className="token-val">{minted.token}</code>
              <button className={`token-copy${copied ? " done" : ""}`} onClick={() => void copyToken()}>
                {copied ? "Copied ✓" : "Copy"}
              </button>
            </div>
            <div className="modal-actions">
              <button className="modal-btn primary" onClick={() => setMinted(null)}>
                Done
              </button>
            </div>
          </div>
        </div>
      )}
      </div>
    </>
  );
}
