/**
 * The pure policy evaluator.
 *
 * Given a compiled policy and a (tool, action) pair, return a decision. No IO,
 * no clock, no randomness — the same inputs always yield the same output, which
 * is exactly what makes the whole thing table-testable.
 *
 * Precedence (deny-by-default, most-restrictive-wins):
 *   1. no grant for the tool          -> DENY  (no_grant_for_tool)
 *   2. action matches a `deny`        -> DENY  (explicit_deny)
 *   3. action matches `require_approval` -> REQUIRE_APPROVAL (approval_required)
 *   4. action matches an `allow`      -> ALLOW (explicit_allow)
 *   5. unresolved target, allow opted in -> REQUIRE_APPROVAL (unresolved_approval)
 *   6. nothing matched                -> DENY  (no_matching_allow / unresolved_target)
 */
import type { CompiledRule, CompiledPolicy } from "./compile.ts";
import type { EngineResult } from "./types.ts";

export interface EvalInput {
  /** The upstream/tool name; must match a grant's `tool`. */
  readonly tool: string;
  /** The normalized action, e.g. `pr:merge`. */
  readonly action: string;
  /**
   * The request's log-safe target (URL path / MCP label), or null for
   * REACHABILITY mode ("could this ever happen"): a target-scoped
   * allow/require_approval counts as matchable, a target-scoped deny does
   * not (it is evadable via some other target). Enforcement always passes
   * a string.
   */
  readonly target: string | null;
  /**
   * The target string exists but could not be RESOLVED statically: it carries a
   * part whose value is only known at run time (`curl $URL`). The action is
   * fully decidable; only the argument is not.
   *
   * An unresolved target can never satisfy a target GLOB — unprovable is not
   * matched, in either direction, so it neither earns a scoped allow nor trips a
   * scoped deny. Rules that do not look at targets at all (bare-string rules,
   * `targets: null`) are unaffected and behave exactly as they always do: an
   * unscoped `deny: [exec:curl]` is absolute and still fires here, which is the
   * whole reason this reaches the engine instead of being refused before it.
   */
  readonly unresolved?: boolean;
}

function firstMatch(
  rules: readonly CompiledRule[],
  action: string,
  target: string | null,
  clause: "deny" | "require_approval" | "allow",
  unresolved = false,
): CompiledRule | null {
  for (const r of rules) {
    if (!r.action.re.test(action)) continue;
    if (r.targets === null) return r;
    // An unresolved target is unprovable, and unprovable never matches a glob.
    // Uniform across all three clauses: `curl $URL` neither earns a scoped
    // `curl https://api.internal/*` allow nor trips a scoped deny.
    if (unresolved) continue;
    if (target === null) {
      if (clause !== "deny") return r; // reachable via some target
      continue; // a scoped deny is evadable — not a reachability guarantee
    }
    if (r.targets.some((t) => t.re.test(target))) return r;
  }
  return null;
}

/** Evaluate one action. Pure and synchronous. */
export function evaluate(policy: CompiledPolicy, input: EvalInput): EngineResult {
  const grant = policy.grants.get(input.tool);
  if (!grant) {
    return { decision: "deny", reason: "no_grant_for_tool", matched: null, pattern: null };
  }

  const unresolved = input.unresolved === true;

  const denied = firstMatch(grant.deny, input.action, input.target, "deny", unresolved);
  if (denied !== null) {
    return {
      decision: "deny",
      reason: "explicit_deny",
      matched: "deny",
      pattern: denied.action.source,
      message: denied.message ?? undefined,
    };
  }

  const approval = firstMatch(
    grant.requireApproval,
    input.action,
    input.target,
    "require_approval",
    unresolved,
  );
  if (approval !== null) {
    return {
      decision: "require_approval",
      reason: "approval_required",
      matched: "require_approval",
      pattern: approval.action.source,
      message: approval.message ?? undefined,
    };
  }

  const allowed = firstMatch(grant.allow, input.action, input.target, "allow", unresolved);
  if (allowed !== null) {
    return { decision: "allow", reason: "explicit_allow", matched: "allow", pattern: allowed.action.source };
  }

  if (unresolved) {
    // The action is decidable and nothing unscoped claimed it. An allow rule
    // whose ACTION matches may opt in to asking a human rather than blocking:
    // "the agent wants to run `curl $URL`; the argument cannot be verified".
    // Checked AFTER the allow pass, so an unscoped allow still allows outright
    // rather than pointlessly prompting.
    const opted = grant.allow.find(
      (r) => r.onUnresolved === "approve" && r.action.re.test(input.action),
    );
    if (opted) {
      return {
        decision: "require_approval",
        reason: "unresolved_approval",
        matched: "allow",
        pattern: opted.action.source,
        message: opted.message ?? undefined,
      };
    }
    // Denied, but for the accurate reason: the target could not be resolved,
    // not "no rule mentioned this action".
    return { decision: "deny", reason: "unresolved_target", matched: null, pattern: null };
  }

  return { decision: "deny", reason: "no_matching_allow", matched: null, pattern: null };
}

/**
 * Budget check, kept pure by taking the current window count as input. The
 * proxy supplies the already-spent count from the request log; the engine just
 * compares. `requested` is how many actions this request would perform (>1 for
 * an MCP batch). Returns `true` when performing them all stays within budget.
 */
export function withinBudget(
  policy: CompiledPolicy,
  allowedActionsInWindow: number,
  requested = 1,
): boolean {
  if (policy.maxActionsPerHour === null) return true;
  return allowedActionsInWindow + requested <= policy.maxActionsPerHour;
}

/**
 * Per-upstream budget check. Pure, like `withinBudget`: takes the already-spent
 * ALLOWED action count for THIS upstream in the window. Returns `true` when the
 * upstream has no configured ceiling, else whether performing `requested` more
 * actions stays within it. The global ceiling (`withinBudget`) is checked
 * separately and independently.
 */
export function withinUpstreamBudget(
  policy: CompiledPolicy,
  upstream: string,
  allowedForUpstreamInWindow: number,
  requested = 1,
): boolean {
  const limit = policy.perUpstreamActionsPerHour.get(upstream);
  if (limit === undefined) return true;
  return allowedForUpstreamInWindow + requested <= limit;
}

/**
 * Per-delegation budget check. Pure, like its siblings: takes the already-
 * spent ALLOWED action count for THIS delegated sub-token in the window. One
 * ceiling applies to every sub-token, each counted separately — additive on
 * top of the parent's agent ceiling, which is checked independently.
 */
export function withinDelegationBudget(
  policy: CompiledPolicy,
  allowedForDelegationInWindow: number,
  requested = 1,
): boolean {
  if (policy.perDelegationActionsPerHour === null) return true;
  return allowedForDelegationInWindow + requested <= policy.perDelegationActionsPerHour;
}

/**
 * The budget cost of a single action: the MAX weight among matching
 * `budget.weights` globs, or 1 by default. Pure. Weights only ever raise cost
 * above the baseline 1 (max-wins: deterministic regardless of map order, and a
 * broad cheap glob can never under-charge a risky action).
 */
export function actionCost(policy: CompiledPolicy, action: string): number {
  let cost = 1;
  for (const w of policy.budgetWeights) {
    if (w.weight > cost && w.pattern.re.test(action)) cost = w.weight;
  }
  return cost;
}

/**
 * The number of DISTINCT human approvers an action needs: the MAX matching
 * `quorum` entry, or 1 by default. Pure. Max-wins (strictest applies), so a
 * broad low quorum can never weaken a specific higher one.
 */
export function approvalQuorum(policy: CompiledPolicy, action: string): number {
  let n = 1;
  for (const q of policy.quorums) {
    if (q.n > n && q.pattern.re.test(action)) n = q.n;
  }
  return n;
}

/** An agent's effective hourly ceiling and where it came from. */
export interface AgentCeiling {
  /** Effective hourly action ceiling; null = unlimited. */
  readonly limit: number | null;
  /** True when `limit` came from a `per_agent` entry rather than the global default. */
  readonly override: boolean;
}

/**
 * Select an agent's effective hourly ceiling. Pure. `per_agent` OVERRIDES the
 * global `max_actions_per_hour` for the agents it names — lower or higher —
 * and agents it doesn't name fall back to that default. The caller needs
 * `override` to pick the right reason code (agent_budget_exceeded vs
 * budget_exceeded).
 */
export function agentCeiling(policy: CompiledPolicy, agentId: string): AgentCeiling {
  const own = policy.perAgentActionsPerHour.get(agentId);
  if (own !== undefined) return { limit: own, override: true };
  return { limit: policy.maxActionsPerHour, override: false };
}

/**
 * Whether a named agent's approval overlay requires a human nod for `action`.
 * Pure. The overlay only ADDS friction (an allowed action becomes
 * require_approval); it is applied in a dispatch()-layer gate, never here — the
 * engine stays free of agent identity.
 */
export function agentRequiresApproval(
  policy: CompiledPolicy,
  agentId: string,
  action: string,
  target: string | null,
): boolean {
  const rules = policy.perAgentApproval.get(agentId);
  if (rules === undefined) return false;
  for (const r of rules) {
    if (!r.action.re.test(action)) continue;
    if (r.targets === null) return true; // unscoped rule → any target
    // A null target is reachability/unknown (e.g. an MCP batch, or explain with
    // no target). The overlay only ADDS friction, so worst-case = clamp — the
    // same rule `firstMatch` uses for a scoped require_approval clause, NOT the
    // scoped-deny "evadable" exception.
    if (target === null) return true;
    if (r.targets.some((t) => t.re.test(target))) return true;
  }
  return false;
}
