/**
 * Pure "why?" trace for a single (tool, action): what the policy engine says,
 * and what every proxy layer around it would do RIGHT NOW, in dispatch order —
 * kill-switch -> engine -> JIT grant -> risk step-up -> budgets.
 *
 * Reuses the proxy's own primitives (evaluate, agentCeiling, globMatch) so the
 * explanation cannot drift from enforcement. Pure and synchronous: the CLI
 * shell gathers all live state (stores, log counts) and passes it in.
 */
import { evaluate, agentCeiling, agentRequiresApproval, actionCost } from "../policy/evaluate.ts";
import { globMatch } from "../policy/glob.ts";
import { matchTripwire } from "../policy/tripwire.ts";
import { resolveResponseLimit } from "../response/limit.ts";
import type { CompiledPolicy } from "../policy/compile.ts";
import type { Decision, EngineResult, ReasonCode } from "../policy/types.ts";

export interface ExplainInputs {
  readonly policy: CompiledPolicy;
  readonly tool: string;
  readonly action: string;
  /** The target to test, or null for worst-case reachability. */
  readonly target: string | null;
  readonly agentId: string;
  /** Kill-switch state for the agent (null = not revoked). */
  readonly revoked: { readonly reason: string } | null;
  /** Active, un-revoked JIT grants for this agent. */
  readonly activeGrants: readonly {
    readonly id: string;
    readonly actions: readonly string[];
    readonly expiresAt: number;
  }[];
  /** Allowed actions already spent in the current window, per ceiling. */
  readonly spentAgent: number;
  readonly spentUpstream: number;
  /** Current risk level from the log when step_up is configured; else null. */
  readonly riskLevel: "low" | "elevated" | "high" | null;
  /** Whether the schedule window is open now (null = no schedule configured). */
  readonly scheduleOpen: boolean | null;
  /** First-use state for this (tool, action): true forwarded-before, false
   *  would-be-first, null = no first_use or the action is out of `only` scope. */
  readonly firstUseSeen: boolean | null;
  /** Approvals config, for context lines. */
  readonly approvals: { readonly ttlSeconds: number; readonly rememberSeconds: number };
}

export type GrantEffect = "widens_gap" | "widens_approval" | "never_overrides_deny" | "not_needed";

export interface ExplainReport {
  readonly engine: EngineResult;
  /** How many rules for this action are target-conditional — the CLI uses
   *  this to say "pass a target to test them" when run without one. */
  readonly scopedRules: number;
  /** Schedule state: true open, false closed, null = no schedule. */
  readonly scheduleOpen: boolean | null;
  /** First-use state: true seen, false first, null = not gated. */
  readonly firstUseSeen: boolean | null;
  /** Flows for which the explained action is a SINK (gated if a matching source
   *  was seen this session). Empty when none. Stateless — explain has no live
   *  facts, so this states the conditional rule, not a live verdict. */
  readonly flowSinks: readonly {
    readonly effect: "deny" | "require_approval";
    readonly sources: readonly string[];
    readonly withinSeconds: number;
  }[];
  /** Set when the explained action matches a tripwire (attempting it revokes the
   *  agent). null otherwise. */
  readonly tripwire: { readonly note: string | null } | null;
  /** Pin rules for which the explained action is CONSTRAINED (a pivot to a new
   *  target unit escalates). Empty when none. Stateless — explain has no live
   *  facts, so this states the conditional rule, not a live verdict. */
  readonly pins: readonly {
    readonly effect: "require_approval" | "deny";
    readonly ruleIndex: number;
  }[];
  /** Response-size cap that applies to this (action, target); null = uncapped.
   *  Stateless — states the configured cap, like flow/pin lines. */
  readonly responseCap: { readonly maxBytes: number; readonly onExceed: "truncate" | "deny" } | null;
  /** True when this agent's approval overlay clamps this action to
   *  require_approval. Stateless — states the configured rule. */
  readonly perAgentApproval: boolean;
  readonly revoked: boolean;
  readonly grantMatch: {
    readonly id: string;
    readonly pattern: string;
    readonly expiresAt: number;
  } | null;
  readonly grantEffect: GrantEffect | null;
  readonly stepUp: {
    readonly windowMs: number;
    readonly riskLevel: string | null;
    readonly wouldUpgrade: boolean;
  } | null;
  readonly agentBudget: {
    readonly limit: number | null;
    readonly override: boolean;
    readonly spent: number;
    /** This action's budget cost (default 1; raised by `budget.weights`). */
    readonly cost: number;
    readonly wouldExceed: boolean;
  };
  readonly upstreamBudget: {
    readonly limit: number;
    readonly spent: number;
    readonly wouldExceed: boolean;
  } | null;
  readonly approvals: { readonly ttlSeconds: number; readonly rememberSeconds: number };
  /** The headline: the first blocking layer in dispatch order, or the pass-through verdict. */
  readonly effective: { readonly decision: Decision; readonly reason: ReasonCode };
}

export function buildExplain(inputs: ExplainInputs): ExplainReport {
  const engine = evaluate(inputs.policy, { tool: inputs.tool, action: inputs.action, target: inputs.target });

  // Target-conditional rules covering this action (any clause). When explain
  // runs without a target, the verdict above is worst-case reachability and
  // the shell points the user at these.
  const grantRules = inputs.policy.grants.get(inputs.tool);
  const overlayRules = inputs.policy.perAgentApproval.get(inputs.agentId) ?? [];
  const scopedRules =
    (grantRules
      ? [...grantRules.deny, ...grantRules.requireApproval, ...grantRules.allow].filter(
          (r) => r.targets !== null && r.action.re.test(inputs.action),
        ).length
      : 0) +
    overlayRules.filter((r) => r.targets !== null && r.action.re.test(inputs.action)).length;

  // First active grant whose pattern matches the action (grants are already
  // agent-scoped and un-revoked — the shell filters, mirroring dispatch()).
  let grantMatch: ExplainReport["grantMatch"] = null;
  for (const g of inputs.activeGrants) {
    const pattern = g.actions.find((p) => globMatch(p, inputs.action));
    if (pattern !== undefined) {
      grantMatch = { id: g.id, pattern, expiresAt: g.expiresAt };
      break;
    }
  }
  const grantEffect: GrantEffect | null =
    grantMatch === null
      ? null
      : engine.decision === "allow"
        ? "not_needed"
        : engine.reason === "explicit_deny"
          ? "never_overrides_deny"
          : engine.decision === "require_approval"
            ? "widens_approval"
            : "widens_gap";

  // Effective verdict, in dispatch order. 1) kill-switch, 2) engine, 3) grant.
  let effective: { decision: Decision; reason: ReasonCode };
  if (inputs.revoked !== null) {
    effective = { decision: "deny", reason: "token_revoked" };
  } else if (grantEffect === "widens_gap" || grantEffect === "widens_approval") {
    effective = { decision: "allow", reason: "jit_grant" };
  } else {
    effective = { decision: engine.decision, reason: engine.reason };
  }

  // Schedule windows clamp a permitting verdict when closed — before step-up,
  // exactly as dispatch orders it.
  if (inputs.policy.schedule && inputs.scheduleOpen === false && effective.decision !== "deny") {
    effective =
      inputs.policy.schedule.onClosed === "deny"
        ? { decision: "deny", reason: "schedule_closed" }
        : { decision: "require_approval", reason: "approval_required" };
  }

  // First-use gating clamps a first-ever allow — before step-up, as dispatch
  // orders it; a jit_grant allow is exempt (the grant is the human decision).
  if (
    inputs.policy.firstUse &&
    inputs.firstUseSeen === false &&
    effective.decision === "allow" &&
    effective.reason !== "jit_grant"
  ) {
    effective =
      inputs.policy.firstUse.onFirst === "deny"
        ? { decision: "deny", reason: "first_use_denied" }
        : { decision: "require_approval", reason: "approval_required" };
  }

  // 4) Risk step-up: an ALLOW upgrades when configured and risk is high now.
  const stepUp =
    inputs.policy.stepUp === null
      ? null
      : {
          windowMs: inputs.policy.stepUp.windowMs,
          riskLevel: inputs.riskLevel,
          wouldUpgrade: effective.decision === "allow" && inputs.riskLevel === "high",
        };
  if (stepUp?.wouldUpgrade) {
    effective = { decision: "require_approval", reason: "approval_required" };
  }

  // Per-agent approval overlay clamps an allowed action to require_approval —
  // AFTER first-use and step-up (matching dispatch), so it never masks a
  // first_use `on_first: deny`. Standing per-agent friction: applies even to a
  // jit_grant allow (most-restrictive-wins).
  const perAgentApproval = agentRequiresApproval(inputs.policy, inputs.agentId, inputs.action, inputs.target);
  if (perAgentApproval && effective.decision === "allow") {
    effective = { decision: "require_approval", reason: "approval_required" };
  }

  // 5) Budgets, in the proxy's own order: agent ceiling first, then upstream.
  // This action's cost (default 1; raised by `budget.weights`) drives the
  // projection so explain matches enforcement, which bills the same cost.
  const cost = actionCost(inputs.policy, inputs.action);
  const ceiling = agentCeiling(inputs.policy, inputs.agentId);
  const agentBudget = {
    limit: ceiling.limit,
    override: ceiling.override,
    spent: inputs.spentAgent,
    cost,
    wouldExceed: ceiling.limit !== null && inputs.spentAgent + cost > ceiling.limit,
  };
  const upstreamLimit = inputs.policy.perUpstreamActionsPerHour.get(inputs.tool);
  const upstreamBudget =
    upstreamLimit === undefined
      ? null
      : {
          limit: upstreamLimit,
          spent: inputs.spentUpstream,
          wouldExceed: inputs.spentUpstream + cost > upstreamLimit,
        };
  if (effective.decision === "allow" || effective.decision === "require_approval") {
    if (agentBudget.wouldExceed) {
      effective = {
        decision: "deny",
        reason: ceiling.override ? "agent_budget_exceeded" : "budget_exceeded",
      };
    } else if (upstreamBudget !== null && upstreamBudget.wouldExceed) {
      effective = { decision: "deny", reason: "upstream_budget_exceeded" };
    }
  }

  const flowSinks = inputs.policy.flows
    .filter((f) => f.then.some((p) => p.re.test(inputs.action)))
    .map((f) => ({
      effect: f.effect,
      sources: f.when.map((p) => p.source),
      withinSeconds: Math.round(f.withinMs / 1000),
    }));

  const wire = matchTripwire(inputs.policy.tripwires, inputs.action, inputs.target);

  const pins = inputs.policy.pins
    .map((p, i) => ({ p, i }))
    .filter(({ p }) => p.on.some((pat) => pat.re.test(inputs.action)))
    .map(({ p, i }) => ({ effect: p.effect, ruleIndex: i }));

  return {
    engine,
    scopedRules,
    scheduleOpen: inputs.scheduleOpen,
    firstUseSeen: inputs.firstUseSeen,
    flowSinks,
    tripwire: wire ? { note: wire.note } : null,
    pins,
    responseCap: resolveResponseLimit(inputs.policy, inputs.action, inputs.target),
    perAgentApproval,
    revoked: inputs.revoked !== null,
    grantMatch,
    grantEffect,
    stepUp,
    agentBudget,
    upstreamBudget,
    approvals: inputs.approvals,
    effective,
  };
}
