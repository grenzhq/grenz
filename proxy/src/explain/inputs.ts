/**
 * Assemble `ExplainInputs` from raw materials — the single source shared by the
 * `grenz explain` CLI (file-backed stores) and the `/console/explain` endpoint
 * (the proxy's live stores). Keeping the assembly in one place is the whole
 * point: both callers produce byte-identical inputs, so the console can never
 * drift from what the CLI — and, transitively, `dispatch` — decide.
 *
 * The stores are read-only here; given the same materials this is pure.
 */
import type { CompiledPolicy } from "../policy/compile.ts";
import type { ExplainInputs } from "./report.ts";
import type { RequestLog } from "../log/request-log.ts";
import type { RevocationStore } from "../revoke/store.ts";
import type { GrantStore } from "../grant/store.ts";
import { firstUseInScope } from "../policy/first-use.ts";
import { withinSchedule } from "../policy/schedule.ts";
import { scoreRisk } from "../risk/score.ts";

/** Mirrors the proxy's budget window (server.ts BUDGET_WINDOW_MS). */
const BUDGET_WINDOW_MS = 60 * 60 * 1000;

export interface ExplainSources {
  readonly policy: CompiledPolicy;
  readonly agentId: string;
  readonly tool: string;
  readonly action: string;
  /** Concrete target, or null for worst-case reachability. */
  readonly target: string | null;
  readonly now: number;
  /** The request log, or null when there is none yet (CLI offline). */
  readonly log: RequestLog | null;
  readonly revocations: RevocationStore | null;
  readonly grants: GrantStore | null;
  readonly approvals: { readonly ttlSeconds: number; readonly rememberSeconds: number };
}

export function collectExplainInputs(s: ExplainSources): ExplainInputs {
  const { policy, agentId, tool, action, target, now } = s;

  const revokedRec = s.revocations?.get(agentId) ?? undefined;
  const activeGrants = (s.grants?.list(now) ?? [])
    .filter((g) => g.agentId === agentId && !s.revocations?.isRevoked(g.id))
    .map((g) => ({ id: g.id, actions: g.actions, expiresAt: g.expiresAt }));

  // Log-derived state (budget spend, current risk, first-use). No log -> zeros/null.
  let spentAgent = 0;
  let spentUpstream = 0;
  let riskLevel: "low" | "elevated" | "high" | null = null;
  let firstUseSeen: boolean | null = null;
  const firstUseGated = policy.firstUse !== null && firstUseInScope(policy.firstUse, action);
  if (s.log) {
    spentAgent = s.log.countAllowedSince(agentId, now - BUDGET_WINDOW_MS);
    spentUpstream = s.log.countAllowedSinceForUpstream(agentId, tool, now - BUDGET_WINDOW_MS);
    if (policy.stepUp) {
      riskLevel = scoreRisk(s.log.agentActivity(agentId, now - policy.stepUp.windowMs)).level;
    }
    if (firstUseGated && policy.firstUse) {
      const since = policy.firstUse.windowMs === null ? 0 : now - policy.firstUse.windowMs;
      firstUseSeen = s.log.hasForwardedActionSince(agentId, tool, action, since);
    }
  }
  // A gated action with no log yet has never been forwarded — a first use.
  if (firstUseSeen === null && firstUseGated) firstUseSeen = false;

  const scheduleOpen = policy.schedule ? withinSchedule(policy.schedule, now) : null;

  return {
    policy,
    tool,
    action,
    target,
    agentId,
    revoked: revokedRec ? { reason: revokedRec.reason } : null,
    activeGrants,
    spentAgent,
    spentUpstream,
    riskLevel,
    scheduleOpen,
    firstUseSeen,
    approvals: s.approvals,
  };
}
