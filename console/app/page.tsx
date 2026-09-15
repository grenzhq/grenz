"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Nav, PageHead } from "./Nav";
import { Select, type SelectOption } from "./Select";
import { Timeline } from "./Timeline";
import { AttentionStrip } from "./Attention";
import { RequestDrawer } from "./Drawer";

interface Summary {
  window_hours: number;
  total: number;
  allow: number;
  deny: number;
  approvalGranted: number;
  approvalDenied: number;
  approvalExpired: number;
  rememberedGrant: number;
  rememberedDeny: number;
  pending: number;
  would_block: Array<{ tool: string; action: string; decision: string; n: number }>;
}

interface RequestRow {
  ts: number;
  agentId: string;
  upstream: string;
  tool: string;
  action: string;
  method: string;
  target: string;
  decision: "allow" | "deny" | "require_approval";
  reason: string;
  forwarded: boolean;
  status: number | null;
}

interface Approval {
  id: string;
  agentId: string;
  tool: string;
  action: string;
  target: string;
  expiresAt: number;
}

interface BroadGrant {
  pattern: string;
  matches: string[];
}

interface UpstreamExposure {
  upstream: string;
  type: string;
  enumerable: boolean;
  autoAllow: string[];
  requiresApproval: string[];
  broadGrants: BroadGrant[];
  rawPatterns?: { allow: string[]; requireApproval: string[]; deny: string[] };
}

interface DelegationExposure {
  id: string;
  note: string;
  actions: string[];
  expiresInSeconds: number;
}

interface BlastRadius {
  agent: string;
  severity: "low" | "elevated" | "high";
  upstreams: UpstreamExposure[];
  delegations: DelegationExposure[];
  reasons: string[];
}

interface AgentBudget {
  agent: string;
  limit: number | null;
  override: boolean;
  spent: number;
  upstreams: Array<{ upstream: string; limit: number; spent: number }>;
}

interface AgentRisk {
  agent: string;
  level: "low" | "elevated" | "high";
  score: number;
  reasons: string[];
  total: number;
  deny: number;
}

interface Grant {
  id: string;
  agent: string;
  actions: string[];
  reason: string;
  expires_at: number;
  revoked: boolean;
}

type DefenseKind = "trap" | "trifecta" | "identity" | "exfil" | "gate" | "rate" | "policy";

interface FirewallEvent {
  id: number;
  ts: number;
  agentId: string;
  tool: string;
  action: string;
  target: string;
  decision: "allow" | "deny" | "require_approval";
  reason: string;
  forwarded: boolean;
  shadow: boolean;
  occurrences: number;
  defense: { code: string; label: string; kind: DefenseKind; blurb: string; severity: string };
}

function severityBadgeClass(severity: BlastRadius["severity"] | undefined): string {
  if (severity === "high") return "deny";
  if (severity === "elevated") return "require_approval";
  return "allow";
}

const POLL_MS = 5000;

function timeAgo(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`http ${res.status}`);
  return (await res.json()) as T;
}

export default function Page() {
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
  // A clock for the timeline's hour buckets, refreshed each poll.
  const [nowTick, setNowTick] = useState(() => Date.now());
  // Request-log filters + the row opened in the detail drawer.
  const [drawerReq, setDrawerReq] = useState<RequestRow | null>(null);
  const [reqQuery, setReqQuery] = useState("");
  const [reqDecision, setReqDecision] = useState("all");
  const [reqAgent, setReqAgent] = useState("all");
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

  const approvalTotal =
    (summary?.approvalGranted ?? 0) + (summary?.approvalDenied ?? 0) + (summary?.approvalExpired ?? 0);
  const total = summary?.total ?? 0;
  const allowN = summary?.allow ?? 0;
  const denyN = summary?.deny ?? 0;
  const pendingN = summary?.pending ?? 0;
  const pct = (n: number) => (total > 0 ? (n / total) * 100 : 0);

  const agentsSeen = Array.from(new Set(requests.map((r) => r.agentId).filter(Boolean)));
  const filtered = requests.filter((r) => {
    if (reqDecision !== "all" && r.decision !== reqDecision) return false;
    if (reqAgent !== "all" && r.agentId !== reqAgent) return false;
    if (reqQuery.trim()) {
      const q = reqQuery.trim().toLowerCase();
      const hay = `${r.tool}:${r.action} ${r.target ?? ""} ${r.agentId ?? ""} ${r.reason ?? ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const filtersActive = reqDecision !== "all" || reqAgent !== "all" || reqQuery.trim() !== "";

  return (
    <>
      <Nav
        right={
          <span className="status">
            <span className={`dot ${online ? "ok" : "off"}`} />
            {online ? "connected" : "proxy offline"}
          </span>
        }
      />
      <div className="wrap">
        <PageHead title="Overview">
        Every request your agents make, decided the moment it happens.{" "}
        <span className="allow">Allowed</span> passes through, <span className="deny">denied</span> is stopped at the
        door, and anything <span className="appr">held</span> is waiting on you.
      </PageHead>

      {!online && (
        <div className="offline">
          Can’t reach the Grenz proxy. Start it with <code>grenz run</code>, or set
          <code> GRENZ_PROXY_URL</code> / <code>GRENZ_ADMIN_TOKEN</code>.
        </div>
      )}

      <section className="perimeter">
        <div className="perimeter-head">
          <span className={`perimeter-state${online ? "" : " down"}`}>
            <span className="pulse-dot" />
            {online ? "Perimeter active" : "Perimeter offline"}
          </span>
          <span className="perimeter-scope">guarding {summary?.window_hours ?? 24}h of traffic</span>
        </div>
        <div className="perimeter-readout">
          <div className="big-stat">
            <span className="bn">{total}</span>
            <span className="bl">requests screened</span>
          </div>
          <div className="verdict-split">
            <div className="vs allow">
              <span className="vn">{allowN}</span>
              <span className="vl">allowed</span>
            </div>
            <div className="vs deny">
              <span className="vn">{denyN}</span>
              <span className="vl">denied</span>
            </div>
            <div className="vs appr">
              <span className="vn">{approvalTotal}</span>
              <span className="vl">held</span>
            </div>
            <div className="vs">
              <span className="vn">{pendingN}</span>
              <span className="vl">pending</span>
            </div>
          </div>
        </div>
        <div className="ratio-bar">
          {total > 0 ? (
            <>
              {allowN > 0 && <span className="ratio allow" style={{ width: `${pct(allowN)}%` }} />}
              {denyN > 0 && <span className="ratio deny" style={{ width: `${pct(denyN)}%` }} />}
              {approvalTotal > 0 && <span className="ratio appr" style={{ width: `${pct(approvalTotal)}%` }} />}
            </>
          ) : (
            <span className="ratio-empty" />
          )}
        </div>
      </section>

      <AttentionStrip risk={risk} firewall={firewall} approvals={approvals} />

      <h2>
        Throughput <span className="sub">requests / hour · last {summary?.window_hours ?? 24}h</span>
      </h2>
      <div className="card tl-card">
        <Timeline requests={requests} windowHours={summary?.window_hours ?? 24} now={nowTick} />
      </div>

      <h2>Firewall activity</h2>
      <div className="card">
        {firewall.length === 0 ? (
          <div className="empty">No agent has tripped a defense yet.</div>
        ) : (
          firewall.map((e) => {
            const observed = e.shadow; // logged under --shadow: observed, not enforced-blocked
            return (
              <div
                className={`fw-row${freshIds.has(e.id) ? " fresh" : ""}`}
                data-kind={e.defense.kind}
                key={e.id}
              >
                <span className="fw-chip" data-kind={e.defense.kind}>
                  {e.defense.label}
                  {e.occurrences > 1 ? <span className="fw-count"> ×{e.occurrences}</span> : null}
                </span>
                <div className="fw-body">
                  <div className="fw-line">
                    <span className="fw-agent">{e.agentId}</span>
                    <span className="muted"> · </span>
                    <span className="action">
                      {e.tool}:{e.action}
                    </span>
                    {e.target ? <span className="muted"> · {e.target}</span> : null}
                    {observed ? <span className="fw-shadow">shadow · would block</span> : null}
                  </div>
                  <div className="fw-blurb">{e.defense.blurb}</div>
                </div>
                <span className="fw-when">{timeAgo(e.ts)}</span>
              </div>
            );
          })
        )}
      </div>

      {risk.length > 0 && (
        <>
          <h2>Agent risk</h2>
          <div className="card risk-strip">
            {risk.map((a) => (
              <span className="risk-agent" key={a.agent} title={a.reasons.join(", ") || "no findings"}>
                <span className="risk-name">{a.agent}</span>
                <span className={`badge ${severityBadgeClass(a.level)}`}>
                  {a.level} · {a.score}
                </span>
              </span>
            ))}
          </div>
        </>
      )}

      <h2 id="pending-approvals">Pending approvals</h2>
      <div className="card">
        {approvals.length === 0 ? (
          <div className="empty">Nothing waiting on you.</div>
        ) : (
          approvals.map((a) => (
            <div className="approval-row" key={a.id}>
              <div className="meta">
                <span className="action">
                  {a.tool}:{a.action}
                </span>{" "}
                <span className="muted">
                  · {a.agentId} · {a.target} · expires {Math.max(0, Math.round((a.expiresAt - Date.now()) / 1000))}s
                </span>
              </div>
              <div className="btns">
                <button
                  className="approve"
                  disabled={busy === a.id}
                  onClick={() => void decide(a.id, "approve")}
                >
                  Approve
                </button>
                <button className="deny" disabled={busy === a.id} onClick={() => void decide(a.id, "deny")}>
                  Deny
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {(summary?.would_block?.length ?? 0) > 0 && (
        <>
          <h2>Shadow would-block</h2>
          <div className="card">
            {summary!.would_block.map((w, i) => (
              <div className="approval-row" key={`${w.tool}-${w.action}-${i}`}>
                <div className="meta">
                  <span className="action">
                    {w.tool}:{w.action}
                  </span>{" "}
                  <span className="muted">
                    · would-{w.decision} × {w.n}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {budgets.some((b) => b.limit !== null || b.upstreams.length > 0) && (
        <>
          <h2>
            Budgets <span className="sub">last 1h</span>
          </h2>
          <div className="card">
            {budgets.map((b) => (
              <div className="approval-row" key={b.agent}>
                <div className="meta">
                  <span className="action">{b.agent}</span>{" "}
                  <span className="muted">
                    · {b.spent}/{b.limit ?? "unlimited"}
                    {b.override ? " (override)" : ""}
                    {b.upstreams.map((u) => ` · ${u.upstream} ${u.spent}/${u.limit}`).join("")}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <h2>
        Recent requests <span className="sub">{filtered.length}{filtersActive ? ` of ${requests.length}` : ""}</span>
      </h2>
      <div className="req-filters">
        <input
          className="req-search"
          placeholder="Search action, target, agent, reason…"
          value={reqQuery}
          onChange={(e) => setReqQuery(e.target.value)}
          aria-label="search requests"
        />
        <Select
          ariaLabel="filter by decision"
          className="req-filter"
          value={reqDecision}
          onChange={setReqDecision}
          options={[
            { value: "all", label: "All decisions" },
            { value: "allow", label: "Allowed" },
            { value: "deny", label: "Denied" },
            { value: "require_approval", label: "Held" },
          ]}
        />
        <Select
          ariaLabel="filter by agent"
          className="req-filter"
          value={reqAgent}
          onChange={setReqAgent}
          options={[
            { value: "all", label: "All agents" },
            ...agentsSeen.map<SelectOption>((a) => ({ value: a, label: a })),
          ]}
        />
        {filtersActive && (
          <button
            className="req-clear"
            onClick={() => {
              setReqQuery("");
              setReqDecision("all");
              setReqAgent("all");
            }}
          >
            Clear
          </button>
        )}
      </div>
      <div className="card scroll">
        {filtered.length === 0 ? (
          <div className="empty">{filtersActive ? "No requests match these filters." : "No requests yet."}</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Agent</th>
                <th>Action</th>
                <th>Target</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr
                  key={`${r.ts}-${i}`}
                  className="row-click"
                  onClick={() => setDrawerReq(r)}
                  tabIndex={0}
                  onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setDrawerReq(r)}
                >
                  <td className="muted">{timeAgo(r.ts)}</td>
                  <td>{r.agentId}</td>
                  <td className="action">
                    {r.tool}:{r.action}
                  </td>
                  <td className="target" title={r.target}>
                    {r.target}
                  </td>
                  <td>
                    <span className={`badge ${r.decision}`}>{r.decision}</span>
                  </td>
                  <td className="muted">{r.reason}</td>
                  <td className="muted">{r.forwarded ? (r.status ?? "—") : "blocked"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <h2>
        Blast radius
        {blast && <span className={`badge ${severityBadgeClass(blast.severity)}`}> {blast.severity}</span>}
      </h2>
      {(blast?.upstreams?.length ?? 0) === 0 ? (
        <div className="card">
          <div className="empty">No upstreams to analyze yet.</div>
        </div>
      ) : (
        <div className="exposure-grid">
          {blast!.upstreams.map((u) => (
            <div className="exposure-card" key={u.upstream}>
              <h3>
                {u.upstream} <span className="muted">({u.type})</span>
              </h3>
              {u.enumerable ? (
                <>
                  <div className="exposure-row">
                    <span className="badge allow">{u.autoAllow.length} auto-allow</span>
                    <span className="badge require_approval">{u.requiresApproval.length} approval</span>
                  </div>
                  {u.broadGrants.map((bg) => (
                    <div className="warn-row" key={bg.pattern}>
                      ⚠ &quot;{bg.pattern}&quot; reaches {bg.matches.join(", ")}
                    </div>
                  ))}
                </>
              ) : (
                <div className="muted">not enumerable — raw grant patterns only</div>
              )}
            </div>
          ))}
        </div>
      )}

      <h2>Live delegations</h2>
      <div className="card">
        {(blast?.delegations.length ?? 0) === 0 ? (
          <div className="empty">No active delegations.</div>
        ) : (
          blast!.delegations.map((d) => (
            <div className="approval-row" key={d.id}>
              <div className="meta">
                <span className="action">{d.id}</span>{" "}
                <span className="muted">
                  · [{d.actions.join(", ")}] · expires in {d.expiresInSeconds}s
                  {d.note ? ` · ${d.note}` : ""}
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      <h2>Active grants</h2>
      <div className="card">
        {grants.length === 0 ? (
          <div className="empty">No active grants.</div>
        ) : (
          grants.map((g) => (
            <div className="approval-row" key={g.id}>
              <div className="meta">
                <span className="action">{g.id}</span>{" "}
                <span className="muted">
                  · {g.agent} · [{g.actions.join(", ")}] · expires{" "}
                  {Math.max(0, Math.round((g.expires_at - Date.now()) / 1000))}s
                  {g.reason ? ` · ${g.reason}` : ""}
                  {g.revoked ? " · REVOKED" : ""}
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      <RequestDrawer req={drawerReq} onClose={() => setDrawerReq(null)} />
      </div>
    </>
  );
}
