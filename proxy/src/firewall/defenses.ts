/**
 * Firewall defense taxonomy — operational visibility ONLY.
 *
 * The proxy stamps a `ReasonCode` on every decision it writes to the plain
 * request log. Most of those codes are ordinary bookkeeping (an allow, an
 * approval settling, a transport error). A subset are the firewall actually
 * doing its job: stopping an agent that has been pushed — by a poisoned input
 * or otherwise — into reaching somewhere it should not.
 *
 * This module maps that subset to a small, human-legible descriptor so the
 * console can surface "which defense fired, and why it matters" instead of one
 * undifferentiated wall of grey denies. It is a pure lookup over the reason
 * string — no I/O, no state. It reads the same truncatable log everything else
 * does: this is live visibility, not an audit trail and not evidence.
 */

/** Threat category — drives colour and grouping in the feed. */
export type DefenseKind =
  | "trap" // honeytokens / tripwires: touching it is itself the signal
  | "trifecta" // lethal-trifecta sequence + lateral-movement gates
  | "identity" // the actor's token: revoked, expired, stolen, over-reaching
  | "exfil" // data leaving: DLP, response size cap, egress origin
  | "gate" // behavioural gates: first-use novelty, schedule window
  | "rate" // budget ceilings
  | "policy"; // deny-by-default: nothing permitted this

export type DefenseSeverity = "high" | "elevated" | "base";

export interface DefenseInfo {
  /** The ReasonCode this describes. */
  readonly code: string;
  /** Short human name, e.g. "Tripwire". */
  readonly label: string;
  readonly kind: DefenseKind;
  /** One line, threat-framed. Never audit/forensic/compliance language. */
  readonly blurb: string;
  readonly severity: DefenseSeverity;
}

const info = (
  code: string,
  kind: DefenseKind,
  severity: DefenseSeverity,
  label: string,
  blurb: string,
): DefenseInfo => ({ code, label, kind, blurb, severity });

/**
 * Defense reason codes → descriptor. A code absent from this map is NOT a
 * defense (an allow, an approval-flow step, a transport error) and
 * `classifyDefense` returns null for it. Keeping the map and the exclusion set
 * exhaustive over `ReasonCode` is enforced by the completeness test.
 */
export const DEFENSE_INFO: Readonly<Record<string, DefenseInfo>> = {
  // — trap: the touch is the tell —
  tripwire: info(
    "tripwire",
    "trap",
    "high",
    "Tripwire",
    "The agent touched a wired action — its token was revoked on the spot.",
  ),
  decoy_token: info(
    "decoy_token",
    "trap",
    "high",
    "Decoy token",
    "A planted credential no legitimate config should carry — a strong compromise signal. Revoked.",
  ),
  decoy_upstream: info(
    "decoy_upstream",
    "trap",
    "high",
    "Decoy upstream",
    "The agent reached for a bait service no policy allows. Revoked.",
  ),

  // — trifecta: dangerous sequence / lateral movement —
  flow_denied: info(
    "flow_denied",
    "trifecta",
    "high",
    "Taint-flow",
    "A read-then-exfiltrate sequence was cut mid-chain.",
  ),
  pin_violation: info(
    "pin_violation",
    "trifecta",
    "high",
    "Session pin",
    "The agent tried to pivot to a target it hadn't already touched.",
  ),

  // — identity: the actor's token —
  token_revoked: info(
    "token_revoked",
    "identity",
    "high",
    "Kill-switch",
    "This agent's token is revoked; every request is refused.",
  ),
  revocation_stale: info(
    "revocation_stale",
    "identity",
    "high",
    "Fleet fail-closed",
    "The signed revocation set is stale, so traffic is denied until it refreshes.",
  ),
  agent_token_expired: info(
    "agent_token_expired",
    "identity",
    "elevated",
    "Expired token",
    "The agent's token is past its lifetime.",
  ),
  wrong_listener: info(
    "wrong_listener",
    "identity",
    "high",
    "Wrong listener",
    "A valid token arrived on the admin listener — a possible token-theft signal.",
  ),
  delegation_scope: info(
    "delegation_scope",
    "identity",
    "elevated",
    "Over-reach",
    "A delegated sub-token asked for more than it was granted.",
  ),
  delegation_target_scope: info(
    "delegation_target_scope",
    "identity",
    "elevated",
    "Out-of-scope target",
    "A delegated sub-token reached a target outside its granted reach.",
  ),
  agent_target_scope: info(
    "agent_target_scope",
    "identity",
    "elevated",
    "Out-of-scope target",
    "The agent's token reached a target outside the reach it is confined to.",
  ),
  agent_action_scope: info(
    "agent_action_scope",
    "identity",
    "elevated",
    "Out-of-scope action",
    "The agent's token asked for an action outside the set it is confined to.",
  ),

  // — exfil: data leaving —
  dlp_secret_detected: info(
    "dlp_secret_detected",
    "exfil",
    "high",
    "DLP block",
    "A secret was detected in the outbound request and blocked.",
  ),
  response_too_large: info(
    "response_too_large",
    "exfil",
    "elevated",
    "Read cap",
    "An allowed read's response exceeded its size limit and was withheld.",
  ),
  egress_blocked: info(
    "egress_blocked",
    "exfil",
    "elevated",
    "Egress guard",
    "The outbound URL resolved off the upstream's allowed origin.",
  ),

  // — gate: behavioural —
  first_use_denied: info(
    "first_use_denied",
    "gate",
    "elevated",
    "First-use",
    "The agent's first-ever attempt at this action was denied.",
  ),
  schedule_closed: info(
    "schedule_closed",
    "gate",
    "elevated",
    "Off-hours",
    "The request fell outside the policy's allowed window.",
  ),

  // — rate: budgets —
  budget_exceeded: info(
    "budget_exceeded",
    "rate",
    "elevated",
    "Rate limit",
    "The agent's hourly action budget was exhausted.",
  ),
  upstream_budget_exceeded: info(
    "upstream_budget_exceeded",
    "rate",
    "elevated",
    "Rate limit",
    "The hourly budget for this upstream was exhausted.",
  ),
  agent_budget_exceeded: info(
    "agent_budget_exceeded",
    "rate",
    "elevated",
    "Rate limit",
    "The agent's own budget ceiling was exhausted.",
  ),
  delegation_budget_exceeded: info(
    "delegation_budget_exceeded",
    "rate",
    "elevated",
    "Rate limit",
    "This delegated sub-token's hourly budget was exhausted.",
  ),

  // — policy: deny-by-default —
  explicit_deny: info(
    "explicit_deny",
    "policy",
    "base",
    "Policy deny",
    "An explicit rule refuses this action.",
  ),
  no_matching_allow: info(
    "no_matching_allow",
    "policy",
    "base",
    "Deny-by-default",
    "Nothing in the policy permits this action.",
  ),
  no_grant_for_tool: info(
    "no_grant_for_tool",
    "policy",
    "base",
    "Deny-by-default",
    "The policy grants this agent nothing on this tool.",
  ),
  unknown_upstream: info(
    "unknown_upstream",
    "policy",
    "base",
    "Unknown upstream",
    "The agent named an upstream that isn't configured — deny-by-default.",
  ),
};

/** All classified defense codes — the filter list the feed queries the log by. */
export const DEFENSE_CODES: readonly string[] = Object.keys(DEFENSE_INFO);

/** Descriptor for a defense reason code, or null if the code is not a defense. */
export function classifyDefense(reason: string): DefenseInfo | null {
  return DEFENSE_INFO[reason] ?? null;
}
