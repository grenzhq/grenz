/**
 * Core decision types for the Grenz policy engine.
 *
 * The engine is PURE and SYNCHRONOUS: it never performs IO. It maps a
 * (tool, action) pair against a compiled policy and returns a decision plus a
 * structured, log-safe reason code. Nothing in this module ever touches, holds,
 * or references credential material.
 */

/** The three terminal decisions a policy can produce for an action. */
export type Decision = "allow" | "deny" | "require_approval";

/**
 * Structured, machine-readable reason codes. These are safe to put in logs,
 * HTTP responses, and error messages — none of them ever carry a value that
 * could be a credential.
 */
export type ReasonCode =
  // Policy-engine outcomes
  | "explicit_allow"
  | "explicit_deny"
  | "approval_required"
  | "no_matching_allow"
  | "no_grant_for_tool"
  // Proxy-layer outcomes (enforced around the pure engine)
  | "budget_exceeded"
  // Per-upstream budget: a single tool's hourly ceiling was exceeded
  | "upstream_budget_exceeded"
  // Per-agent budget: an agent's own (per_agent override) ceiling was exceeded
  | "agent_budget_exceeded"
  // Per-delegation budget: one delegated sub-token's own hourly ceiling was
  // exceeded (additive on top of the parent's agent ceiling)
  | "delegation_budget_exceeded"
  | "unknown_upstream"
  | "invalid_token"
  // Agent token expiry: a token matched a configured agent past its `expires_at`.
  // Masked on the wire as invalid_token (byte-identical to an unknown-token 401);
  // the true reason lives only in the operator's plane (log/doctor/run banner).
  | "agent_token_expired"
  // Delegation: a live sub-token whose ROOT agent is gone (deleted from config
  // or past its own expires_at). There is nothing left to attenuate from, so it
  // resolves to no principal. Masked on the wire as invalid_token.
  | "delegation_root_missing"
  | "malformed_policy"
  | "credential_missing"
  | "vault_error"
  | "unsupported_request"
  | "approvals_unavailable"
  // Kill-switch: the agent's token has been revoked
  | "token_revoked"
  // Fleet revocation, fail-closed: the signed revocation set is stale and the
  // operator opted into denying ALL requests until a fresh one lands
  | "revocation_stale"
  // Response minimization: an allowed read's body exceeded its policy size cap
  // and the rule's on_exceed was `deny`
  | "response_too_large"
  // Delegation: a delegated token reached beyond its attenuated ACTION scope
  | "delegation_scope"
  // Delegation: a delegated token reached a TARGET outside its attenuated reach
  | "delegation_target_scope"
  // Agent scope: a first-class agent (or a delegation under it) reached a TARGET
  // outside the reach its grenz.yaml `targets` confine it to
  | "agent_target_scope"
  // Agent scope: same, but for an ACTION outside its grenz.yaml `actions` list
  | "agent_action_scope"
  // Agent policy: the principal carries a profile name the running PolicyStore
  // does not know (load-time validation should prevent it; this is the request-
  // path safety net). No profile CONTENTS in the reason — only that it failed.
  | "agent_policy_unresolved"
  // Schedule window: the request fell outside the policy's allowed hours
  | "schedule_closed"
  // First-use gate: the agent's first-ever forward of this action was blocked
  | "first_use_denied"
  // Taint-flow gate: a sink fired after a matching source this session
  | "flow_denied"
  // Tripwire: an action/target the operator declared a hair-trigger revoke on
  | "tripwire"
  // Decoy honeytoken: a decoy GRENZ_TOKEN was presented. Masked on the wire as
  // invalid_token; the true reason is logged. The toucher is revoked.
  | "decoy_token"
  // Decoy honeytoken: a decoy upstream was touched. Masked on the wire as
  // no_matching_allow; the true reason is logged. The toucher is revoked.
  | "decoy_upstream"
  // Socket mode: an agent route arrived on the ADMIN (TCP) listener. In socket
  // mode agent traffic must come over the unix socket; a valid token seen here
  // is a theft signal — logged and notified, never auto-revoked in v1 (a merely
  // misconfigured legitimate agent would self-destruct).
  | "wrong_listener"
  // Pin gate: the session pivoted to a target unit it had not already touched
  | "pin_violation"
  // Unresolved target: the ACTION was decidable but the target carried a part
  // that is only known at run time (`curl $URL`). The action reached the engine
  // and no unscoped rule claimed it, so it denies. Distinct from
  // `exec_undecidable`, which means nothing could be named at all.
  | "unresolved_target"
  // Same shape, but an allow rule opted in with `on_unresolved: approve`, so a
  // human is asked instead of the command being blocked outright.
  | "unresolved_approval"
  // Egress guard: the outbound URL resolved off the upstream's configured origin
  | "egress_blocked"
  // Just-in-time grant: a static gap or require_approval was widened by an
  // operator-minted temporary grant. Never applies to an explicit_deny.
  | "jit_grant"
  // Approval-broker outcomes (Gate 2)
  | "approval_granted"
  | "approval_denied"
  | "approval_expired"
  | "approval_capacity"
  // Client disconnected while its request was blocked on approval: the pending
  // approval was cancelled and the action was NOT performed (never forwarded).
  | "approval_abandoned"
  // Approval memory: a recent human decision was reused for an identical request
  | "approval_remembered_grant"
  | "approval_remembered_deny"
  // Content inspection (DLP)
  | "dlp_secret_detected"
  // Bash guard: the command line parsed, but what it will actually run cannot be
  // decided statically — an expansion or substitution in a word, a shell/eval
  // that takes its program from somewhere Grenz cannot read, or a glob binary
  // that resolves at exec time. Deliberately NOT an action the engine can allow:
  // an `exec:*` grant must not become a way to permit obfuscation.
  | "exec_undecidable"
  // Bash guard: the command line did not parse as bash, or the parse was lossy
  // (the node set contradicted the raw source). Never best-effort read.
  | "exec_parse_failed"
  | "upstream_error"
  | "internal_error";

/** Which grant clause a request matched against. */
export type MatchedClause = "deny" | "require_approval" | "allow" | null;

/** The result of evaluating a single (tool, action) against a compiled policy. */
export interface EngineResult {
  readonly decision: Decision;
  readonly reason: ReasonCode;
  /** Which clause produced the decision, for observability. */
  readonly matched: MatchedClause;
  /**
   * The exact pattern string that matched (e.g. `"pr:*"`), for observability.
   * This is drawn only from the policy source, never from request data, so it
   * can never contain a credential. `null` when nothing matched.
   */
  readonly pattern: string | null;
  /**
   * Optional operator-authored remediation hint from the matched rule (surfaced
   * on a deny). Static policy text — never request-derived, so log-safe exactly
   * like `pattern`. Absent when no rule matched or the matched rule had none.
   */
  readonly message?: string;
}
