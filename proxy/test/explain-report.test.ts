import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { buildExplain, type ExplainInputs } from "../src/explain/report.ts";
import { renderExplainLines } from "../src/cli/explain.ts";

const POLICY_YAML = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny: [pr:merge]
    require_approval: [issue:update]
budget:
  max_actions_per_hour: 100
  per_agent:
    ci-bot: 2
  per_upstream:
    github: 50
step_up:
  window_seconds: 900
`;

function loadPolicy(yaml: string = POLICY_YAML): CompiledPolicy {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

const policy = loadPolicy();

function inputs(over: Partial<ExplainInputs>): ExplainInputs {
  return {
    policy,
    tool: "github",
    action: "repo:read",
    target: null,
    agentId: "claude-code",
    revoked: null,
    activeGrants: [],
    spentAgent: 0,
    spentUpstream: 0,
    riskLevel: "low",
    scheduleOpen: null,
    firstUseSeen: null,
    approvals: { ttlSeconds: 300, rememberSeconds: 0 },
    ...over,
  };
}

const GRANT = { id: "grx", actions: ["pr:*", "issue:*"], expiresAt: 9_999 };

describe("buildExplain: engine + grants", () => {
  test("plain allow passes through", () => {
    const r = buildExplain(inputs({}));
    expect(r.engine.decision).toBe("allow");
    expect(r.effective).toEqual({ decision: "allow", reason: "explicit_allow" });
    expect(r.grantMatch).toBeNull();
    expect(r.grantEffect).toBeNull();
  });

  test("a grant never overrides an explicit deny", () => {
    const r = buildExplain(inputs({ action: "pr:merge", activeGrants: [GRANT] }));
    expect(r.engine.reason).toBe("explicit_deny");
    expect(r.grantMatch?.pattern).toBe("pr:*");
    expect(r.grantEffect).toBe("never_overrides_deny");
    expect(r.effective).toEqual({ decision: "deny", reason: "explicit_deny" });
  });

  test("a grant fills a policy gap", () => {
    const r = buildExplain(inputs({ action: "pr:create", activeGrants: [GRANT] }));
    expect(r.engine.reason).toBe("no_matching_allow");
    expect(r.grantEffect).toBe("widens_gap");
    expect(r.effective).toEqual({ decision: "allow", reason: "jit_grant" });
  });

  test("a grant lifts a require_approval", () => {
    const r = buildExplain(inputs({ action: "issue:update", activeGrants: [GRANT] }));
    expect(r.engine.decision).toBe("require_approval");
    expect(r.grantEffect).toBe("widens_approval");
    expect(r.effective).toEqual({ decision: "allow", reason: "jit_grant" });
  });

  test("a grant on an already-allowed action is not needed", () => {
    const g = { id: "g2", actions: ["repo:*"], expiresAt: 9_999 };
    const r = buildExplain(inputs({ activeGrants: [g] }));
    expect(r.grantEffect).toBe("not_needed");
    expect(r.effective.reason).toBe("explicit_allow");
  });

  test("a grant also fills no_grant_for_tool", () => {
    const g = { id: "g3", actions: ["issue:read"], expiresAt: 9_999 };
    const r = buildExplain(
      inputs({ tool: "linear", action: "issue:read", activeGrants: [g], spentUpstream: 0 }),
    );
    expect(r.engine.reason).toBe("no_grant_for_tool");
    expect(r.grantEffect).toBe("widens_gap");
    expect(r.effective).toEqual({ decision: "allow", reason: "jit_grant" });
  });
});

describe("buildExplain: kill-switch + step-up", () => {
  test("revoked trumps everything, even an allow", () => {
    const r = buildExplain(inputs({ revoked: { reason: "manual" } }));
    expect(r.revoked).toBe(true);
    expect(r.effective).toEqual({ decision: "deny", reason: "token_revoked" });
  });

  test("high risk upgrades an allow to approval", () => {
    const r = buildExplain(inputs({ riskLevel: "high" }));
    expect(r.stepUp?.wouldUpgrade).toBe(true);
    expect(r.effective).toEqual({ decision: "require_approval", reason: "approval_required" });
  });

  test("elevated risk does not upgrade", () => {
    const r = buildExplain(inputs({ riskLevel: "elevated" }));
    expect(r.stepUp?.wouldUpgrade).toBe(false);
    expect(r.effective.decision).toBe("allow");
  });

  test("an already-require_approval verdict is not double-upgraded", () => {
    const r = buildExplain(inputs({ action: "issue:update", riskLevel: "high" }));
    expect(r.stepUp?.wouldUpgrade).toBe(false);
    expect(r.effective.decision).toBe("require_approval");
  });

  test("no step_up config -> stepUp is null", () => {
    const noStep = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
`);
    const r = buildExplain(inputs({ policy: noStep, riskLevel: null }));
    expect(r.stepUp).toBeNull();
  });
});

describe("buildExplain: budgets", () => {
  test("agent default ceiling: headroom at spent+1 == limit, exceeded past it", () => {
    const ok = buildExplain(inputs({ spentAgent: 99 }));
    expect(ok.agentBudget.wouldExceed).toBe(false);
    expect(ok.effective.decision).toBe("allow");

    const over = buildExplain(inputs({ spentAgent: 100 }));
    expect(over.agentBudget).toEqual({ limit: 100, override: false, spent: 100, cost: 1, wouldExceed: true });
    expect(over.effective).toEqual({ decision: "deny", reason: "budget_exceeded" });
  });

  test("per-agent override ceiling reports agent_budget_exceeded", () => {
    const r = buildExplain(inputs({ agentId: "ci-bot", spentAgent: 2 }));
    expect(r.agentBudget.override).toBe(true);
    expect(r.effective).toEqual({ decision: "deny", reason: "agent_budget_exceeded" });
  });

  test("upstream ceiling reports upstream_budget_exceeded", () => {
    const r = buildExplain(inputs({ spentUpstream: 50 }));
    expect(r.upstreamBudget).toEqual({ limit: 50, spent: 50, wouldExceed: true });
    expect(r.effective).toEqual({ decision: "deny", reason: "upstream_budget_exceeded" });
  });

  test("agent ceiling is checked before upstream", () => {
    const r = buildExplain(inputs({ spentAgent: 100, spentUpstream: 50 }));
    expect(r.effective.reason).toBe("budget_exceeded");
  });

  test("no per_upstream entry -> upstreamBudget null", () => {
    const r = buildExplain(inputs({ tool: "linear", action: "x" }));
    expect(r.upstreamBudget).toBeNull();
  });

  test("budgets do not change an explicit deny", () => {
    const r = buildExplain(inputs({ action: "pr:merge", spentAgent: 100 }));
    expect(r.agentBudget.wouldExceed).toBe(true); // reported...
    expect(r.effective.reason).toBe("explicit_deny"); // ...but not the verdict
  });

  test("budgets DO gate a require_approval verdict", () => {
    const r = buildExplain(inputs({ action: "issue:update", spentAgent: 100 }));
    expect(r.effective).toEqual({ decision: "deny", reason: "budget_exceeded" });
  });

  test("explain with a target enforces; without, reachability + scopedRules count", () => {
    const scoped = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow:
      - repo:read
      - action: "pr:*"
        targets: ["/repos/acme/*"]
`);
    // Enforcement: matching target allows, other target default-denies.
    const hit = buildExplain(inputs({ policy: scoped, action: "pr:create", target: "/repos/acme/x/pulls" }));
    expect(hit.effective.decision).toBe("allow");
    const miss = buildExplain(inputs({ policy: scoped, action: "pr:create", target: "/repos/other/x" }));
    expect(miss.effective.reason).toBe("no_matching_allow");
    // Reachability: null target -> allow reachable, report counts scoped rules.
    const reach = buildExplain(inputs({ policy: scoped, action: "pr:create", target: null }));
    expect(reach.effective.decision).toBe("allow");
    expect(reach.scopedRules).toBe(1);
    // An action with no scoped rules reports 0.
    expect(buildExplain(inputs({ policy: scoped, action: "repo:read", target: null })).scopedRules).toBe(0);
  });

  test("a closed schedule clamps the effective verdict to on_closed", () => {
    const sched = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  windows:
    - days: [mon]
      start: "09:00"
      end: "17:00"
  on_closed: deny
`);
    // Open: verdict is the engine allow.
    const open = buildExplain(inputs({ policy: sched, action: "repo:read", scheduleOpen: true }));
    expect(open.effective.decision).toBe("allow");
    // Closed: clamped to schedule_closed.
    const closed = buildExplain(inputs({ policy: sched, action: "repo:read", scheduleOpen: false }));
    expect(closed.effective).toEqual({ decision: "deny", reason: "schedule_closed" });
    expect(closed.scheduleOpen).toBe(false);
  });

  test("a closed require_approval schedule clamps allow to approval", () => {
    const sched = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  windows: [{ days: [mon], start: "09:00", end: "17:00" }]
  on_closed: require_approval
`);
    const closed = buildExplain(inputs({ policy: sched, action: "repo:read", scheduleOpen: false }));
    expect(closed.effective).toEqual({ decision: "require_approval", reason: "approval_required" });
  });

  test("first use clamps the effective verdict to on_first", () => {
    const fu = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
first_use:
  on_first: require_approval
  only: ["pr:*"]
`);
    const seen = buildExplain(inputs({ policy: fu, action: "pr:create", firstUseSeen: true }));
    expect(seen.effective.decision).toBe("allow");
    const first = buildExplain(inputs({ policy: fu, action: "pr:create", firstUseSeen: false }));
    expect(first.effective).toEqual({ decision: "require_approval", reason: "approval_required" });
    expect(first.firstUseSeen).toBe(false);
  });

  test("first_use on_first deny clamps to first_use_denied", () => {
    const fu = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
first_use:
  on_first: deny
  only: [repo:read]
`);
    const first = buildExplain(inputs({ policy: fu, action: "repo:read", firstUseSeen: false }));
    expect(first.effective).toEqual({ decision: "deny", reason: "first_use_denied" });
  });

  test("weighted action budget reports the action's cost and projects spend", () => {
    const w = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:merge, repo:read]
budget:
  max_actions_per_hour: 100
  weights:
    "pr:merge": 10
`);
    // 95 spent + a cost-10 action would exceed 100.
    const r = buildExplain(inputs({ policy: w, action: "pr:merge", spentAgent: 95 }));
    expect(r.agentBudget.cost).toBe(10);
    expect(r.agentBudget.wouldExceed).toBe(true);
    // A cheap action (cost 1) at 95 spent is fine.
    const cheap = buildExplain(inputs({ policy: w, action: "repo:read", spentAgent: 95 }));
    expect(cheap.agentBudget.cost).toBe(1);
    expect(cheap.agentBudget.wouldExceed).toBe(false);
  });
});

describe("renderExplainLines", () => {
  const denyMsgPolicy = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny:
      - action: pr:merge
        message: "open a PR and request review in #eng"
`);

  test("a denied action's remediation message appears in the output", () => {
    const report = buildExplain(inputs({ policy: denyMsgPolicy, action: "pr:merge", target: "/x" }));
    const text = renderExplainLines(report, {
      agentId: "claude-code",
      tool: "github",
      action: "pr:merge",
      target: "/x",
      policy: denyMsgPolicy,
    }).join("\n");
    expect(text).toContain("open a PR and request review in #eng");
    expect(text).toContain('matched deny "pr:merge"'); // the pattern line is preserved
  });

  test("a denied action with no message renders no hint line", () => {
    const report = buildExplain(inputs({ action: "pr:merge", target: "/x" }));
    const text = renderExplainLines(report, {
      agentId: "claude-code",
      tool: "github",
      action: "pr:merge",
      target: "/x",
      policy,
    }).join("\n");
    expect(text).not.toContain("hint:");
  });
});

describe("buildExplain: flow sinks", () => {
  const flowPolicy = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
flows:
  - when: ["*:read"]
    then: ["pr:merge"]
    effect: require_approval
    within_seconds: 1800
`);

  test("a sink action populates flowSinks", () => {
    const r = buildExplain(inputs({ policy: flowPolicy, action: "pr:merge" }));
    expect(r.flowSinks.length).toBe(1);
    expect(r.flowSinks[0]!.sources).toEqual(["*:read"]);
    expect(r.flowSinks[0]!.effect).toBe("require_approval");
    expect(r.flowSinks[0]!.withinSeconds).toBe(1800);
  });

  test("a non-sink action has no flowSinks", () => {
    const r = buildExplain(inputs({ policy: flowPolicy, action: "repo:read" }));
    expect(r.flowSinks).toEqual([]);
  });

  test("renderExplainLines prints a flow: line for a sink", () => {
    const r = buildExplain(inputs({ policy: flowPolicy, action: "pr:merge" }));
    const text = renderExplainLines(r, {
      agentId: "claude-code",
      tool: "github",
      action: "pr:merge",
      target: null,
      policy: flowPolicy,
    }).join("\n");
    expect(text).toContain("flow:");
    expect(text).toContain("*:read");
    expect(text).toContain("1800s");
  });
});

describe("buildExplain: tripwires", () => {
  const wirePolicy = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "pr:merge"
    note: "off-limits"
`);

  test("a tripwired action populates tripwire", () => {
    const r = buildExplain(inputs({ policy: wirePolicy, action: "pr:merge" }));
    expect(r.tripwire).toEqual({ note: "off-limits" });
  });

  test("a non-tripwired action has null tripwire", () => {
    const r = buildExplain(inputs({ policy: wirePolicy, action: "repo:read" }));
    expect(r.tripwire).toBeNull();
  });

  test("renderExplainLines prints a loud tripwire line", () => {
    const r = buildExplain(inputs({ policy: wirePolicy, action: "pr:merge" }));
    const text = renderExplainLines(r, {
      agentId: "claude-code",
      tool: "github",
      action: "pr:merge",
      target: null,
      policy: wirePolicy,
    }).join("\n");
    expect(text).toContain("tripwire:");
    expect(text).toContain("REVOKES");
  });
});

describe("buildExplain: per-agent approval overlay", () => {
  const overlayPolicy = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
`);
  const ctx = (action: string) => ({ agentId: "claude-code", tool: "github", action, target: null, policy: overlayPolicy });

  test("clamps a listed action to require_approval and flags the report", () => {
    const r = buildExplain(inputs({ policy: overlayPolicy, action: "pr:merge" }));
    expect(r.engine.decision).toBe("allow");
    expect(r.perAgentApproval).toBe(true);
    expect(r.effective).toEqual({ decision: "require_approval", reason: "approval_required" });
    const lines = renderExplainLines(r, ctx("pr:merge"));
    expect(lines.some((l) => l.includes("per-agent:"))).toBe(true);
  });

  test("an unlisted action is not flagged and renders no per-agent line", () => {
    const r = buildExplain(inputs({ policy: overlayPolicy, action: "repo:read" }));
    expect(r.perAgentApproval).toBe(false);
    expect(r.effective.decision).toBe("allow");
    const lines = renderExplainLines(r, ctx("repo:read"));
    expect(lines.some((l) => l.includes("per-agent:"))).toBe(false);
  });

  test("a first_use on_first:deny is NOT masked by the overlay (verdict stays deny)", () => {
    const p = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: ["pr:merge"]
first_use:
  on_first: deny
  only: ["pr:merge"]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
`);
    const r = buildExplain(inputs({ policy: p, action: "pr:merge", firstUseSeen: false }));
    expect(r.effective).toEqual({ decision: "deny", reason: "first_use_denied" });
    expect(r.perAgentApproval).toBe(true); // the rule is still stated (stateless line)
  });

  const scopedPolicy = loadPolicy(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
approvals:
  per_agent:
    claude-code:
      - { action: "pr:merge", targets: ["/repos/acme/*"] }
`);

  test("target-scoped overlay clamps only for a matching target", () => {
    const match = buildExplain(inputs({ policy: scopedPolicy, action: "pr:merge", target: "/repos/acme/web" }));
    expect(match.perAgentApproval).toBe(true);
    expect(match.effective).toEqual({ decision: "require_approval", reason: "approval_required" });

    const miss = buildExplain(inputs({ policy: scopedPolicy, action: "pr:merge", target: "/repos/other/web" }));
    expect(miss.perAgentApproval).toBe(false);
    expect(miss.effective.decision).toBe("allow");
  });

  test("target-scoped overlay: a null target clamps and is counted as worst-case", () => {
    const r = buildExplain(inputs({ policy: scopedPolicy, action: "pr:merge", target: null }));
    expect(r.perAgentApproval).toBe(true);
    expect(r.effective).toEqual({ decision: "require_approval", reason: "approval_required" });
    expect(r.scopedRules).toBeGreaterThan(0); // the scoped overlay counts toward the worst-case note
  });
});
