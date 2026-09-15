import { test, expect, describe } from "bun:test";
import { renderMetrics, type MetricsInput } from "../src/telemetry/metrics.ts";

const SAMPLE: MetricsInput = {
  decisions: { allow: 412, deny: 37 },
  approvals: { granted: 8, denied: 2, expired: 1 },
  approvalsPending: 2,
  delegationsActive: 0,
  grantsActive: 1,
  agentsRevoked: 0,
  shadowWouldBlock: 5,
  policyVersion: 7,
  policySecondsSincePull: 42,
  revocationsFleet: 2,
  revocationSetVersion: 12,
  revocationSecondsSincePull: 45,
};

describe("renderMetrics", () => {
  test("emits decision counters with labels and values", () => {
    const out = renderMetrics(SAMPLE);
    expect(out).toContain("# TYPE grenz_decisions_total counter");
    expect(out).toContain(`grenz_decisions_total{decision="allow"} 412`);
    expect(out).toContain(`grenz_decisions_total{decision="deny"} 37`);
  });

  test("emits approval counters by outcome", () => {
    const out = renderMetrics(SAMPLE);
    expect(out).toContain("# TYPE grenz_approvals_total counter");
    expect(out).toContain(`grenz_approvals_total{outcome="granted"} 8`);
    expect(out).toContain(`grenz_approvals_total{outcome="denied"} 2`);
    expect(out).toContain(`grenz_approvals_total{outcome="expired"} 1`);
  });

  test("emits point-in-time gauges", () => {
    const out = renderMetrics(SAMPLE);
    expect(out).toContain("# TYPE grenz_approvals_pending gauge");
    expect(out).toContain("grenz_approvals_pending 2");
    expect(out).toContain("# TYPE grenz_delegations_active gauge");
    expect(out).toContain("grenz_delegations_active 0");
    expect(out).toContain("grenz_grants_active 1");
    expect(out).toContain("grenz_agents_revoked 0");
  });

  test("emits the shadow would-block counter", () => {
    const out = renderMetrics(SAMPLE);
    expect(out).toContain("# TYPE grenz_shadow_would_block_total counter");
    expect(out).toContain("grenz_shadow_would_block_total 5");
  });

  test("a fresh (all-zero) proxy renders valid zeros, ending with a newline", () => {
    const zero = renderMetrics({
      decisions: { allow: 0, deny: 0 },
      approvals: { granted: 0, denied: 0, expired: 0 },
      approvalsPending: 0,
      delegationsActive: 0,
      grantsActive: 0,
      agentsRevoked: 0,
      shadowWouldBlock: 0,
      policyVersion: 0,
      policySecondsSincePull: 0,
      revocationsFleet: 0,
      revocationSetVersion: 0,
      revocationSecondsSincePull: 0,
    });
    expect(zero).toContain(`grenz_decisions_total{decision="allow"} 0`);
    expect(zero.endsWith("\n")).toBe(true);
  });

  test("emits signed-distribution gauges as current state, not a timeline", () => {
    const out = renderMetrics(SAMPLE);
    expect(out).toContain("# TYPE grenz_policy_version gauge");
    expect(out).toContain("grenz_policy_version 7");
    expect(out).toContain("# TYPE grenz_policy_seconds_since_pull gauge");
    expect(out).toContain("grenz_policy_seconds_since_pull 42");
    // The HELP text must not imply a retained history of policy activations.
    expect(out).toContain("Current state, not a timeline");
  });

  test("emits fleet revocation gauges as current state, not a timeline", () => {
    const out = renderMetrics(SAMPLE);
    expect(out).toContain("# TYPE grenz_revocations_fleet gauge");
    expect(out).toContain("grenz_revocations_fleet 2");
    expect(out).toContain("# TYPE grenz_revocation_set_version gauge");
    expect(out).toContain("grenz_revocation_set_version 12");
    expect(out).toContain("# TYPE grenz_revocation_seconds_since_pull gauge");
    expect(out).toContain("grenz_revocation_seconds_since_pull 45");
  });

  test("deterministic: same input, same output", () => {
    expect(renderMetrics(SAMPLE)).toBe(renderMetrics(SAMPLE));
  });
});
