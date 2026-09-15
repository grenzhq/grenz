import { test, expect, describe } from "bun:test";
import { compilePolicyObject } from "../src/policy/compile.ts";
import {
  lintPolicy,
  lintWeights,
  lintFlows,
  lintTripwires,
  lintPerAgentKeys,
  type LintFinding,
} from "../src/policy/lint.ts";

function policy(grants: Array<{ tool: string; allow?: string[]; deny?: string[]; require_approval?: string[] }>) {
  const compiled = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants });
  if (!compiled.ok) throw new Error(compiled.error);
  return compiled.policy;
}

const GITHUB_UPSTREAM = { github: { type: "github" } };

function kindsOf(findings: readonly LintFinding[]): string[] {
  return findings.map((f) => f.kind);
}

describe("lintPolicy", () => {
  test("dead pattern: a deny that matches no known action is flagged (typo)", () => {
    const p = policy([{ tool: "github", deny: ["pr:merg"] }]); // typo for pr:merge
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.kind).toBe("dead_pattern");
    expect(findings[0]!.pattern).toBe("pr:merg");
    expect(findings[0]!.clause).toBe("deny");
  });

  test("shadowed pattern: an earlier wildcard shadows a later literal in the same clause", () => {
    const p = policy([{ tool: "github", allow: ["repo:*", "repo:read"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    const shadowed = findings.find((f) => f.kind === "shadowed_pattern");
    expect(shadowed).toBeDefined();
    expect(shadowed!.pattern).toBe("repo:read");
    expect(shadowed!.detail).toContain("repo:*");
  });

  test("shadowed pattern: an exact duplicate flags only the later occurrence", () => {
    const p = policy([{ tool: "github", allow: ["repo:read", "repo:read"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    expect(kindsOf(findings).filter((k) => k === "shadowed_pattern")).toHaveLength(1);
  });

  test("broad grant: an allow pattern reaching 3+ actions is flagged", () => {
    const p = policy([{ tool: "github", allow: ["repo:*"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    const broad = findings.find((f) => f.kind === "broad_grant");
    expect(broad).toBeDefined();
    expect(broad!.pattern).toBe("repo:*");
    expect(broad!.clause).toBe("allow");
  });

  test("broad grant: a require_approval pattern reaching 3+ actions is flagged", () => {
    const p = policy([{ tool: "github", require_approval: ["issue:*"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    const broad = findings.find((f) => f.kind === "broad_grant");
    expect(broad).toBeDefined();
    expect(broad!.clause).toBe("require_approval");
  });

  test("a broad DENY is not flagged (conservative, not a smell)", () => {
    const p = policy([{ tool: "github", deny: ["repo:*"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    expect(findings.some((f) => f.kind === "broad_grant")).toBe(false);
  });

  test("generic mcp upstream produces zero findings regardless of patterns", () => {
    const p = policy([
      { tool: "mcp", allow: ["call:x", "call:x"], deny: ["call:definitely_not_a_real_tool"] },
    ]);
    const findings = lintPolicy(p, { mcp: { type: "mcp" } });
    expect(findings).toEqual([]);
  });

  test("a clean policy produces zero findings", () => {
    const p = policy([{ tool: "github", allow: ["repo:read", "pr:create"], deny: ["pr:merge"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    expect(findings).toEqual([]);
  });

  test("pure — same input, same output", () => {
    const p = policy([{ tool: "github", allow: ["repo:*"] }]);
    expect(lintPolicy(p, GITHUB_UPSTREAM)).toEqual(lintPolicy(p, GITHUB_UPSTREAM));
  });

  test("an earlier TARGET-SCOPED rule does not shadow a later rule", () => {
    const compiled = compilePolicyObject({
      agent: "a", on_behalf_of: "b",
      grants: [{
        tool: "github",
        allow: [{ action: "pr:*", targets: ["/repos/acme/*"] }, "pr:read"],
      }],
    });
    if (!compiled.ok) throw new Error(compiled.error);
    const findings = lintPolicy(compiled.policy, GITHUB_UPSTREAM);
    expect(findings.filter((f) => f.kind === "shadowed_pattern")).toEqual([]);
  });

  test("an earlier UNSCOPED broad rule still shadows", () => {
    const p = policy([{ tool: "github", allow: ["pr:*", "pr:read"] }]);
    const findings = lintPolicy(p, GITHUB_UPSTREAM);
    expect(findings.some((f) => f.kind === "shadowed_pattern" && f.pattern === "pr:read")).toBe(true);
  });
});

describe("lintWeights", () => {
  function wpolicy(over: {
    grants?: Array<{ tool: string; allow?: string[]; deny?: string[] }>;
    budget: {
      max_actions_per_hour?: number;
      per_upstream?: Record<string, number>;
      weights: Record<string, number>;
    };
  }) {
    const compiled = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: over.grants ?? [{ tool: "github", allow: ["repo:read", "pr:merge", "repo:delete"] }],
      budget: over.budget,
    });
    if (!compiled.ok) throw new Error(compiled.error);
    return compiled.policy;
  }

  test("no weights -> no findings", () => {
    const p = wpolicy({ budget: { max_actions_per_hour: 100, weights: { "pr:merge": 10 } } });
    // A benign weight under a high ceiling on one tool: clean.
    expect(lintWeights(p, GITHUB_UPSTREAM)).toHaveLength(0);
  });

  test("unreachable_weight: a cost above an applicable ceiling", () => {
    const p = wpolicy({ budget: { max_actions_per_hour: 20, weights: { "repo:delete": 25 } } });
    const f = lintWeights(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.kind === "unreachable_weight" && x.pattern === "repo:delete")).toBe(true);
    expect(f.find((x) => x.kind === "unreachable_weight")!.detail).toContain("deny");
  });

  test("unreachable_weight: per_upstream ceiling counts too", () => {
    const p = wpolicy({
      budget: { max_actions_per_hour: 1000, per_upstream: { github: 20 }, weights: { "repo:delete": 25 } },
    });
    const f = lintWeights(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.kind === "unreachable_weight")).toBe(true);
  });

  test("dominated_weight: a cheap carve-out under a broader higher weight is dead", () => {
    const p = wpolicy({ budget: { max_actions_per_hour: 1000, weights: { "repo:*": 10, "repo:read": 1 } } });
    const f = lintWeights(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.kind === "dominated_weight" && x.pattern === "repo:read")).toBe(true);
  });

  test("dominated_weight: a later broad higher weight still dominates an earlier specific one", () => {
    const p = wpolicy({ budget: { max_actions_per_hour: 1000, weights: { "repo:read": 1, "repo:*": 10 } } });
    const f = lintWeights(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.kind === "dominated_weight" && x.pattern === "repo:read")).toBe(true);
  });

  test("cross_tool_weight: a glob taxing two tools' vocabularies", () => {
    const p = wpolicy({
      grants: [
        { tool: "github", allow: ["issue:read"] },
        { tool: "linear", allow: ["issue:read"] },
      ],
      budget: { max_actions_per_hour: 1000, weights: { "issue:*": 5 } },
    });
    const f = lintWeights(p, { github: { type: "github" }, linear: { type: "linear" } });
    expect(f.some((x) => x.kind === "cross_tool_weight" && x.pattern === "issue:*")).toBe(true);
  });

  test("`*` global cost is exempt from cross_tool_weight", () => {
    const p = wpolicy({
      grants: [
        { tool: "github", allow: ["issue:read"] },
        { tool: "linear", allow: ["issue:read"] },
      ],
      budget: { max_actions_per_hour: 1000, weights: { "*": 2 } },
    });
    const f = lintWeights(p, { github: { type: "github" }, linear: { type: "linear" } });
    expect(f.some((x) => x.kind === "cross_tool_weight")).toBe(false);
  });
});

describe("lintFlows", () => {
  function fpolicy(flows: Array<{ when: string[]; then: string[] }>) {
    const compiled = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", allow: ["repo:read", "pr:merge"] }],
      flows,
    });
    if (!compiled.ok) throw new Error(compiled.error);
    return compiled.policy;
  }

  test("no flows -> no findings", () => {
    const p = fpolicy([]);
    expect(lintFlows(p, GITHUB_UPSTREAM)).toHaveLength(0);
  });

  test("real when/then patterns -> no findings", () => {
    const p = fpolicy([{ when: ["repo:read"], then: ["pr:merge"] }]);
    expect(lintFlows(p, GITHUB_UPSTREAM)).toHaveLength(0);
  });

  test("a typo'd sink is flagged (side then)", () => {
    const p = fpolicy([{ when: ["repo:read"], then: ["chatt:write"] }]);
    const f = lintFlows(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.side === "then" && x.pattern === "chatt:write")).toBe(true);
  });

  test("a typo'd source is flagged (side when)", () => {
    const p = fpolicy([{ when: ["issu:read"], then: ["pr:merge"] }]);
    const f = lintFlows(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.side === "when" && x.pattern === "issu:read")).toBe(true);
  });
});

describe("lintTripwires", () => {
  function tpolicy(over: {
    grants: Array<{ tool: string; allow?: string[]; deny?: string[] }>;
    tripwires: Array<{ action: string; targets?: string[] }>;
  }) {
    const compiled = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: over.grants,
      tripwires: over.tripwires,
    });
    if (!compiled.ok) throw new Error(compiled.error);
    return compiled.policy;
  }

  test("no tripwires -> no findings", () => {
    const p = tpolicy({ grants: [{ tool: "github", allow: ["repo:read"] }], tripwires: [] });
    expect(lintTripwires(p, GITHUB_UPSTREAM)).toHaveLength(0);
  });

  test("a tripwire overlapping an allowed action is flagged (self-revoke footgun)", () => {
    const p = tpolicy({
      grants: [{ tool: "github", allow: ["repo:read"] }],
      tripwires: [{ action: "repo:read" }],
    });
    const f = lintTripwires(p, GITHUB_UPSTREAM);
    expect(f.some((x) => x.pattern === "repo:read")).toBe(true);
  });

  test("a tripwire on a NON-allowed action is clean", () => {
    const p = tpolicy({
      grants: [{ tool: "github", allow: ["repo:read"] }],
      tripwires: [{ action: "*:admin" }],
    });
    expect(lintTripwires(p, GITHUB_UPSTREAM)).toHaveLength(0);
  });
});

describe("lintPerAgentKeys", () => {
  // Build a policy with per-agent budget ceilings and/or approval overlays.
  function papolicy(opts: {
    budgetPerAgent?: Record<string, number>;
    approvalsPerAgent?: Record<string, Array<string | { action: string; targets?: string[] }>>;
  }) {
    const compiled = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", allow: ["pr:read"] }],
      ...(opts.budgetPerAgent ? { budget: { per_agent: opts.budgetPerAgent } } : {}),
      ...(opts.approvalsPerAgent ? { approvals: { per_agent: opts.approvalsPerAgent } } : {}),
    });
    if (!compiled.ok) throw new Error(compiled.error);
    return compiled.policy;
  }

  test("budget.per_agent key naming no registered agent is flagged", () => {
    const p = papolicy({ budgetPerAgent: { "claude-code-prd": 10 } });
    const f = lintPerAgentKeys(p, ["claude-code-prod"]);
    expect(f).toHaveLength(1);
    expect(f[0]!.map).toBe("budget.per_agent");
    expect(f[0]!.agentId).toBe("claude-code-prd");
    expect(f[0]!.detail).toContain("inert");
  });

  test("approvals.per_agent key naming no registered agent is flagged", () => {
    const p = papolicy({ approvalsPerAgent: { "claude-code-prd": ["pr:merge"] } });
    const f = lintPerAgentKeys(p, ["claude-code-prod"]);
    expect(f).toHaveLength(1);
    expect(f[0]!.map).toBe("approvals.per_agent");
    expect(f[0]!.agentId).toBe("claude-code-prd");
  });

  test("a near-miss key gets a 'did you mean' suggestion of the closest registered id", () => {
    const p = papolicy({ approvalsPerAgent: { "claude-code-prd": ["pr:merge"] } });
    const f = lintPerAgentKeys(p, ["claude-code-prod", "linear-bot"]);
    expect(f[0]!.suggestion).toBe("claude-code-prod");
    expect(f[0]!.detail).toContain("claude-code-prod");
  });

  test("a wholly-unrelated key gets no suggestion (suggestion is null)", () => {
    const p = papolicy({ budgetPerAgent: { zzzzz: 5 } });
    const f = lintPerAgentKeys(p, ["claude-code-prod"]);
    expect(f).toHaveLength(1);
    expect(f[0]!.suggestion).toBeNull();
    expect(f[0]!.detail).not.toContain("did you mean");
  });

  test("a key that IS a registered agent is clean", () => {
    const p = papolicy({
      budgetPerAgent: { "claude-code-prod": 10 },
      approvalsPerAgent: { "claude-code-prod": ["pr:merge"] },
    });
    expect(lintPerAgentKeys(p, ["claude-code-prod"])).toEqual([]);
  });

  test("mixed valid + invalid keys: only the unregistered ones are flagged", () => {
    const p = papolicy({
      budgetPerAgent: { "claude-code-prod": 10, "ghost-agent": 5 },
      approvalsPerAgent: { "linear-bot": ["issue:close"], "stale-id": ["pr:merge"] },
    });
    const f = lintPerAgentKeys(p, ["claude-code-prod", "linear-bot"]);
    expect(f.map((x) => x.agentId).sort()).toEqual(["ghost-agent", "stale-id"]);
  });

  test("empty per-agent maps produce no findings", () => {
    const p = papolicy({});
    expect(lintPerAgentKeys(p, ["claude-code-prod"])).toEqual([]);
  });

  test("pure — same input, same output", () => {
    const p = papolicy({ budgetPerAgent: { "claude-code-prd": 10 } });
    expect(lintPerAgentKeys(p, ["claude-code-prod"])).toEqual(
      lintPerAgentKeys(p, ["claude-code-prod"]),
    );
  });
});
