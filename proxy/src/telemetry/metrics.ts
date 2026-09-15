/**
 * Render Grenz's aggregate operational counts as Prometheus text-exposition
 * format (v0.0.4). Pure and synchronous. Emits only aggregate counts with
 * fixed label identifiers — never an agent id, target, body, or secret.
 */

export interface MetricsInput {
  readonly decisions: { readonly allow: number; readonly deny: number };
  readonly approvals: { readonly granted: number; readonly denied: number; readonly expired: number };
  readonly approvalsPending: number;
  readonly delegationsActive: number;
  readonly grantsActive: number;
  readonly agentsRevoked: number;
  readonly shadowWouldBlock: number;
  /** Running signed-policy version; 0 when the policy is local or unsigned. */
  readonly policyVersion: number;
  /** Seconds since the last verified policy pull; 0 when never pulled. */
  readonly policySecondsSincePull: number;
  /** Agents in the running fleet revocation set. */
  readonly revocationsFleet: number;
  /** Running fleet revocation-set version; 0 when none. */
  readonly revocationSetVersion: number;
  /** Seconds since the last verified revocation pull; 0 when never pulled. */
  readonly revocationSecondsSincePull: number;
}

export function renderMetrics(m: MetricsInput): string {
  const lines: string[] = [
    "# HELP grenz_decisions_total Terminal policy decisions recorded in the local log (includes shadow would-blocks, also counted separately below).",
    "# TYPE grenz_decisions_total counter",
    `grenz_decisions_total{decision="allow"} ${m.decisions.allow}`,
    `grenz_decisions_total{decision="deny"} ${m.decisions.deny}`,
    "# HELP grenz_approvals_total Approval outcomes recorded in the local log.",
    "# TYPE grenz_approvals_total counter",
    `grenz_approvals_total{outcome="granted"} ${m.approvals.granted}`,
    `grenz_approvals_total{outcome="denied"} ${m.approvals.denied}`,
    `grenz_approvals_total{outcome="expired"} ${m.approvals.expired}`,
    "# HELP grenz_approvals_pending Approvals currently blocking on a human decision.",
    "# TYPE grenz_approvals_pending gauge",
    `grenz_approvals_pending ${m.approvalsPending}`,
    "# HELP grenz_delegations_active Live delegated sub-tokens.",
    "# TYPE grenz_delegations_active gauge",
    `grenz_delegations_active ${m.delegationsActive}`,
    "# HELP grenz_grants_active Live just-in-time grants.",
    "# TYPE grenz_grants_active gauge",
    `grenz_grants_active ${m.grantsActive}`,
    "# HELP grenz_agents_revoked Agents currently cut off by the kill-switch.",
    "# TYPE grenz_agents_revoked gauge",
    `grenz_agents_revoked ${m.agentsRevoked}`,
    "# HELP grenz_shadow_would_block_total Requests forwarded under --shadow that the policy would have blocked.",
    "# TYPE grenz_shadow_would_block_total counter",
    `grenz_shadow_would_block_total ${m.shadowWouldBlock}`,
    "# HELP grenz_policy_version Signed policy version running right now (0 when the policy is local or unsigned). Current state, not a timeline.",
    "# TYPE grenz_policy_version gauge",
    `grenz_policy_version ${m.policyVersion}`,
    "# HELP grenz_policy_seconds_since_pull Seconds since the last successful verified policy pull (0 when never pulled). Current state, not a timeline.",
    "# TYPE grenz_policy_seconds_since_pull gauge",
    `grenz_policy_seconds_since_pull ${m.policySecondsSincePull}`,
    "# HELP grenz_revocations_fleet Agents currently cut off fleet-wide by the signed revocation set. Current state, not a timeline.",
    "# TYPE grenz_revocations_fleet gauge",
    `grenz_revocations_fleet ${m.revocationsFleet}`,
    "# HELP grenz_revocation_set_version Signed revocation-set version running right now (0 when none). Current state, not a timeline.",
    "# TYPE grenz_revocation_set_version gauge",
    `grenz_revocation_set_version ${m.revocationSetVersion}`,
    "# HELP grenz_revocation_seconds_since_pull Seconds since the last successful verified revocation pull (0 when never pulled). Current state, not a timeline.",
    "# TYPE grenz_revocation_seconds_since_pull gauge",
    `grenz_revocation_seconds_since_pull ${m.revocationSecondsSincePull}`,
  ];
  return lines.join("\n") + "\n";
}
