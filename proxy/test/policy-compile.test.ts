import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, compilePolicyObject } from "../src/policy/compile.ts";
import { withinBudget, withinUpstreamBudget, withinDelegationBudget, agentCeiling, agentRequiresApproval } from "../src/policy/evaluate.ts";
import { compileGlob } from "../src/policy/glob.ts";

describe("policy compile", () => {
  test("valid policy compiles", () => {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: b\ngrants:\n  - tool: github\n    allow: [repo:read]`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.policy.agent).toBe("a");
      expect(r.policy.onBehalfOf).toBe("b");
      expect(r.policy.grants.has("github")).toBe(true);
    }
  });

  test("defaults empty allow/deny/require_approval arrays", () => {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: b\ngrants:\n  - tool: github`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      const g = r.policy.grants.get("github")!;
      expect(g.allow).toEqual([]);
      expect(g.deny).toEqual([]);
      expect(g.requireApproval).toEqual([]);
    }
  });

  test("a deny rule can carry a log-safe message and omit targets", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", deny: [{ action: "pr:merge", message: "open a PR instead" }] }],
    });
    if (!r.ok) throw new Error(r.error);
    const rule = r.policy.grants.get("github")!.deny[0]!;
    expect(rule.message).toBe("open a PR instead");
    expect(rule.targets).toBe(null); // unconstrained without targets
  });

  test("a bare-string rule has a null message", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", deny: ["pr:merge"] }],
    });
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.grants.get("github")!.deny[0]!.message).toBe(null);
  });

  test("a message over 280 chars is rejected", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", deny: [{ action: "pr:merge", message: "x".repeat(281) }] }],
    });
    expect(r.ok).toBe(false);
  });

  test("malformed: missing required field -> error, fail closed", () => {
    const r = compilePolicyYaml(`on_behalf_of: b\ngrants: []`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("malformed policy");
  });

  test("malformed: unknown key rejected (strict)", () => {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: b\ngrants: []\nsurprise: true`);
    expect(r.ok).toBe(false);
  });

  test("malformed: unknown key inside a grant rejected", () => {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: b\ngrants:\n  - tool: github\n    alloww: [x]`);
    expect(r.ok).toBe(false);
  });

  test("malformed: invalid YAML -> error", () => {
    const r = compilePolicyYaml(`agent: : :\n  - broken`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("malformed policy");
  });

  test("malformed: empty document -> error", () => {
    const r = compilePolicyYaml(``);
    expect(r.ok).toBe(false);
  });

  test("malformed: duplicate grant for same tool -> error", () => {
    const r = compilePolicyYaml(
      `agent: a\non_behalf_of: b\ngrants:\n  - tool: github\n    allow: [x]\n  - tool: github\n    allow: [y]`,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("duplicate grant");
  });

  test("malformed: non-positive budget rejected", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], budget: { max_actions_per_hour: 0 } });
    expect(r.ok).toBe(false);
  });

  test("budget parsed, else null", () => {
    const withBudget = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], budget: { max_actions_per_hour: 5 } });
    const noBudget = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    expect(withBudget.ok).toBe(true);
    expect(noBudget.ok).toBe(true);
    if (withBudget.ok) expect(withBudget.policy.maxActionsPerHour).toBe(5);
    if (noBudget.ok) expect(noBudget.policy.maxActionsPerHour).toBe(null);
  });

  test("per_upstream parsed into a map, else empty", () => {
    const withPer = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { max_actions_per_hour: 200, per_upstream: { github: 100, slack: 20 } },
    });
    expect(withPer.ok).toBe(true);
    if (withPer.ok) {
      expect(withPer.policy.perUpstreamActionsPerHour.get("github")).toBe(100);
      expect(withPer.policy.perUpstreamActionsPerHour.get("slack")).toBe(20);
      expect(withPer.policy.perUpstreamActionsPerHour.get("linear")).toBeUndefined();
    }
    const none = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    expect(none.ok).toBe(true);
    if (none.ok) expect(none.policy.perUpstreamActionsPerHour.size).toBe(0);
  });

  test("per_upstream may exist without a global ceiling", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { per_upstream: { github: 5 } },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.policy.maxActionsPerHour).toBe(null);
      expect(r.policy.perUpstreamActionsPerHour.get("github")).toBe(5);
    }
  });

  test("malformed: non-positive per_upstream ceiling rejected", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { per_upstream: { github: 0 } },
    });
    expect(r.ok).toBe(false);
  });

  test("per_agent parsed into a map, else empty", () => {
    const withPer = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { max_actions_per_hour: 500, per_agent: { "ci-bot": 50, batch: 2000 } },
    });
    expect(withPer.ok).toBe(true);
    if (withPer.ok) {
      expect(withPer.policy.perAgentActionsPerHour.get("ci-bot")).toBe(50);
      expect(withPer.policy.perAgentActionsPerHour.get("batch")).toBe(2000);
      expect(withPer.policy.perAgentActionsPerHour.get("nobody")).toBeUndefined();
    }
    const none = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    expect(none.ok).toBe(true);
    if (none.ok) expect(none.policy.perAgentActionsPerHour.size).toBe(0);
  });

  test("per_agent coexists with per_upstream", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { per_agent: { "ci-bot": 5 }, per_upstream: { github: 10 } },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.policy.perAgentActionsPerHour.get("ci-bot")).toBe(5);
      expect(r.policy.perUpstreamActionsPerHour.get("github")).toBe(10);
      expect(r.policy.maxActionsPerHour).toBe(null);
    }
  });

  test("malformed: non-positive per_agent ceiling rejected", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { per_agent: { "ci-bot": 0 } },
    });
    expect(r.ok).toBe(false);
  });

  test("per_delegation parsed into a number, else null", () => {
    const withPer = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: { max_actions_per_hour: 500, per_delegation: 20 },
    });
    expect(withPer.ok).toBe(true);
    if (withPer.ok) expect(withPer.policy.perDelegationActionsPerHour).toBe(20);
    const none = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    expect(none.ok).toBe(true);
    if (none.ok) expect(none.policy.perDelegationActionsPerHour).toBe(null);
  });

  test("malformed: non-positive per_delegation rejected (fails closed)", () => {
    expect(
      compilePolicyObject({
        agent: "a", on_behalf_of: "b", grants: [],
        budget: { per_delegation: 0 },
      }).ok,
    ).toBe(false);
    expect(
      compilePolicyObject({
        agent: "a", on_behalf_of: "b", grants: [],
        budget: { per_delegation: -5 },
      }).ok,
    ).toBe(false);
  });

  test("per_delegation coexists with the other budget keys", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      budget: {
        max_actions_per_hour: 100,
        per_agent: { "ci-bot": 5 },
        per_upstream: { github: 10 },
        per_delegation: 3,
      },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.policy.perDelegationActionsPerHour).toBe(3);
      expect(r.policy.perAgentActionsPerHour.get("ci-bot")).toBe(5);
      expect(r.policy.perUpstreamActionsPerHour.get("github")).toBe(10);
      expect(r.policy.maxActionsPerHour).toBe(100);
    }
  });

  test("malformed: step_up window_seconds out of range rejected", () => {
    const tooShort = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], step_up: { window_seconds: 10 },
    });
    expect(tooShort.ok).toBe(false);
    const tooLong = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], step_up: { window_seconds: 999_999 },
    });
    expect(tooLong.ok).toBe(false);
  });

  test("step_up parsed with default window, else null", () => {
    const withStepUp = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], step_up: {},
    });
    const withCustomWindow = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], step_up: { window_seconds: 60 },
    });
    const noStepUp = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    expect(withStepUp.ok).toBe(true);
    expect(withCustomWindow.ok).toBe(true);
    expect(noStepUp.ok).toBe(true);
    if (withStepUp.ok) expect(withStepUp.policy.stepUp).toEqual({ windowMs: 900_000 });
    if (withCustomWindow.ok) expect(withCustomWindow.policy.stepUp).toEqual({ windowMs: 60_000 });
    if (noStepUp.ok) expect(noStepUp.policy.stepUp).toBe(null);
  });
});

describe("withinBudget", () => {
  const p = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], budget: { max_actions_per_hour: 3 } });
  test("under budget", () => {
    if (!p.ok) throw new Error(p.error);
    expect(withinBudget(p.policy, 0)).toBe(true);
    expect(withinBudget(p.policy, 2)).toBe(true);
  });
  test("at/over budget denies", () => {
    if (!p.ok) throw new Error(p.error);
    expect(withinBudget(p.policy, 3)).toBe(false);
    expect(withinBudget(p.policy, 4)).toBe(false);
  });
  test("no budget is unlimited", () => {
    const np = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    if (!np.ok) throw new Error(np.error);
    expect(withinBudget(np.policy, 1_000_000)).toBe(true);
  });
});

describe("withinUpstreamBudget", () => {
  const p = compilePolicyObject({
    agent: "a", on_behalf_of: "b", grants: [],
    budget: { max_actions_per_hour: 1000, per_upstream: { github: 3 } },
  });

  test("no ceiling for this upstream is unlimited", () => {
    if (!p.ok) throw new Error(p.error);
    expect(withinUpstreamBudget(p.policy, "slack", 1_000_000)).toBe(true);
  });

  test("under the upstream ceiling", () => {
    if (!p.ok) throw new Error(p.error);
    expect(withinUpstreamBudget(p.policy, "github", 0)).toBe(true);
    expect(withinUpstreamBudget(p.policy, "github", 2)).toBe(true);
  });

  test("at/over the upstream ceiling denies", () => {
    if (!p.ok) throw new Error(p.error);
    expect(withinUpstreamBudget(p.policy, "github", 3)).toBe(false);
    expect(withinUpstreamBudget(p.policy, "github", 4)).toBe(false);
  });

  test("a batch pushing over the ceiling denies", () => {
    if (!p.ok) throw new Error(p.error);
    expect(withinUpstreamBudget(p.policy, "github", 2, 1)).toBe(true);
    expect(withinUpstreamBudget(p.policy, "github", 2, 2)).toBe(false);
  });

  test("independent of the global ceiling (no per_upstream = unlimited per-upstream)", () => {
    const globalOnly = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], budget: { max_actions_per_hour: 2 },
    });
    if (!globalOnly.ok) throw new Error(globalOnly.error);
    expect(withinUpstreamBudget(globalOnly.policy, "github", 1_000_000)).toBe(true);
  });
});

describe("agentCeiling", () => {
  const p = compilePolicyObject({
    agent: "a", on_behalf_of: "b", grants: [],
    budget: { max_actions_per_hour: 500, per_agent: { "ci-bot": 50, batch: 2000 } },
  });

  test("an unlisted agent gets the global default, not an override", () => {
    if (!p.ok) throw new Error(p.error);
    expect(agentCeiling(p.policy, "claude-code")).toEqual({ limit: 500, override: false });
  });

  test("an override LOWER than the default wins", () => {
    if (!p.ok) throw new Error(p.error);
    expect(agentCeiling(p.policy, "ci-bot")).toEqual({ limit: 50, override: true });
  });

  test("an override HIGHER than the default wins (override, not min)", () => {
    if (!p.ok) throw new Error(p.error);
    expect(agentCeiling(p.policy, "batch")).toEqual({ limit: 2000, override: true });
  });

  test("no budget at all is unlimited", () => {
    const np = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    if (!np.ok) throw new Error(np.error);
    expect(agentCeiling(np.policy, "claude-code")).toEqual({ limit: null, override: false });
  });

  test("per_agent with no global: listed agent capped, others unlimited", () => {
    const only = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], budget: { per_agent: { "ci-bot": 5 } },
    });
    if (!only.ok) throw new Error(only.error);
    expect(agentCeiling(only.policy, "ci-bot")).toEqual({ limit: 5, override: true });
    expect(agentCeiling(only.policy, "claude-code")).toEqual({ limit: null, override: false });
  });
});

describe("withinDelegationBudget", () => {
  const mk = (per: number | null) => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      ...(per === null ? {} : { budget: { per_delegation: per } }),
    });
    if (!r.ok) throw new Error(r.error);
    return r.policy;
  };

  test("table: unset unlimited; under/at/over; batch pushes over", () => {
    const cases: Array<{ per: number | null; spent: number; requested: number; want: boolean }> = [
      { per: null, spent: 9999, requested: 1, want: true }, // unset -> no per-token cap
      { per: 5, spent: 0, requested: 1, want: true },       // fresh token
      { per: 5, spent: 4, requested: 1, want: true },       // lands exactly on the ceiling
      { per: 5, spent: 5, requested: 1, want: false },      // ceiling consumed
      { per: 5, spent: 3, requested: 2, want: true },       // batch fits exactly
      { per: 5, spent: 3, requested: 3, want: false },      // batch pushes over
      { per: 1, spent: 0, requested: 1, want: true },
      { per: 1, spent: 1, requested: 1, want: false },
    ];
    for (const c of cases) {
      expect(withinDelegationBudget(mk(c.per), c.spent, c.requested)).toBe(c.want);
    }
  });
});

describe("target-scoped rules (compile)", () => {
  test("object form compiles; string form has null targets", () => {
    const r = compilePolicyYaml(`
agent: a
on_behalf_of: b
grants:
  - tool: github
    allow:
      - repo:read
      - action: "pr:*"
        targets: ["/repos/acme/*"]
`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      const g = r.policy.grants.get("github")!;
      expect(g.allow[0]!.action.source).toBe("repo:read");
      expect(g.allow[0]!.targets).toBe(null);
      expect(g.allow[1]!.action.source).toBe("pr:*");
      expect(g.allow[1]!.targets!.length).toBe(1);
      expect(g.allow[1]!.targets![0]!.source).toBe("/repos/acme/*");
      expect(g.allow[1]!.targets![0]!.re.test("/repos/acme/x/pulls/1")).toBe(true);
    }
  });

  test("malformed: empty targets list rejected (fails closed)", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b",
      grants: [{ tool: "github", allow: [{ action: "pr:*", targets: [] }] }],
    });
    expect(r.ok).toBe(false);
  });

  test("malformed: unknown key inside a rule object rejected", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b",
      grants: [{ tool: "github", allow: [{ action: "pr:*", targets: ["/x"], surprise: 1 }] }],
    });
    expect(r.ok).toBe(false);
  });

  test("object rules work in deny and require_approval too", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b",
      grants: [{
        tool: "github",
        deny: [{ action: "repo:delete", targets: ["/repos/prod-*"] }],
        require_approval: [{ action: "pr:merge", targets: ["/repos/infra/*"] }],
      }],
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      const g = r.policy.grants.get("github")!;
      expect(g.deny[0]!.targets!.length).toBe(1);
      expect(g.requireApproval[0]!.targets![0]!.source).toBe("/repos/infra/*");
    }
  });
});

describe("schedule (compile)", () => {
  test("valid schedule compiles: minutes computed, days as a Set, on_closed default deny", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      schedule: { timezone: "America/New_York", windows: [{ days: ["mon", "fri"], start: "09:30", end: "17:00" }] },
    });
    expect(r.ok).toBe(true);
    if (r.ok && r.policy.schedule) {
      expect(r.policy.schedule.timezone).toBe("America/New_York");
      expect(r.policy.schedule.onClosed).toBe("deny");
      const w = r.policy.schedule.windows[0]!;
      expect(w.startMin).toBe(9 * 60 + 30);
      expect(w.endMin).toBe(17 * 60);
      expect(w.days.has("mon")).toBe(true);
      expect(w.days.has("fri")).toBe(true);
      expect(w.days.has("tue")).toBe(false);
    }
  });
  test("absent schedule -> null", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.policy.schedule).toBe(null);
  });
  test("on_closed require_approval is carried through", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      schedule: { windows: [{ days: ["mon"], start: "00:00", end: "23:59" }], on_closed: "require_approval" },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.policy.schedule!.onClosed).toBe("require_approval");
  });
  test("malformed: invalid timezone fails closed", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      schedule: { timezone: "Mars/Olympus", windows: [{ days: ["mon"], start: "09:00", end: "17:00" }] },
    });
    expect(r.ok).toBe(false);
  });
  test("malformed: start >= end fails closed", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      schedule: { windows: [{ days: ["mon"], start: "17:00", end: "09:00" }] },
    });
    expect(r.ok).toBe(false);
  });
  test("malformed: bad HH:MM rejected", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      schedule: { windows: [{ days: ["mon"], start: "9am", end: "17:00" }] },
    });
    expect(r.ok).toBe(false);
  });
  test("malformed: unknown weekday rejected", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [],
      schedule: { windows: [{ days: ["funday"], start: "09:00", end: "17:00" }] },
    });
    expect(r.ok).toBe(false);
  });
  test("malformed: empty windows rejected", () => {
    const r = compilePolicyObject({
      agent: "a", on_behalf_of: "b", grants: [], schedule: { windows: [] },
    });
    expect(r.ok).toBe(false);
  });
});

describe("approvals.per_agent", () => {
  const base = { agent: "a", on_behalf_of: "h", grants: [] };

  test("compiles bare-string (unscoped) rules to any-target matchers", () => {
    const r = compilePolicyObject({
      ...base,
      approvals: { per_agent: { "bot-x": ["*:write", "pr:merge"] } },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const rules = r.policy.perAgentApproval.get("bot-x");
    expect(rules?.length).toBe(2);
    expect(rules!.every((rl) => rl.targets === null)).toBe(true);
    expect(rules!.some((rl) => rl.action.re.test("repo:write"))).toBe(true);
    expect(rules!.some((rl) => rl.action.re.test("pr:merge"))).toBe(true);
    expect(r.policy.perAgentApproval.has("other")).toBe(false);
  });

  test("compiles an object rule with target globs", () => {
    const r = compilePolicyObject({
      ...base,
      approvals: { per_agent: { "bot-x": [{ action: "pr:merge", targets: ["/repos/acme/*"] }] } },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const rules = r.policy.perAgentApproval.get("bot-x")!;
    expect(rules[0]!.action.re.test("pr:merge")).toBe(true);
    expect(rules[0]!.targets?.length).toBe(1);
    expect(rules[0]!.targets!.some((t) => t.re.test("/repos/acme/web"))).toBe(true);
  });

  test("absent block compiles to an empty map", () => {
    const r = compilePolicyObject({ ...base });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.policy.perAgentApproval.size).toBe(0);
  });

  test("strict schema rejects an unknown approvals key", () => {
    const r = compilePolicyObject({ ...base, approvals: { nope: {} } });
    expect(r.ok).toBe(false);
  });

  test("strict schema rejects a message key on an overlay rule", () => {
    const r = compilePolicyObject({
      ...base,
      approvals: { per_agent: { "bot-x": [{ action: "pr:merge", message: "nope" }] } },
    });
    expect(r.ok).toBe(false);
  });

  test("rejects an empty rule list for an agent", () => {
    const r = compilePolicyObject({ ...base, approvals: { per_agent: { "bot-x": [] } } });
    expect(r.ok).toBe(false);
  });
});

describe("agentRequiresApproval", () => {
  const compiled = (perAgent: Record<string, unknown[]>) => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "h", grants: [], approvals: { per_agent: perAgent } });
    if (!r.ok) throw new Error("compile failed");
    return r.policy;
  };

  test("unscoped rule matches any target (incl. null)", () => {
    const p = compiled({ "bot-x": ["*:write"] });
    expect(agentRequiresApproval(p, "bot-x", "repo:write", "/repos/o/r")).toBe(true);
    expect(agentRequiresApproval(p, "bot-x", "repo:write", null)).toBe(true);
  });
  test("no match for an unlisted action", () => {
    const p = compiled({ "bot-x": ["*:write"] });
    expect(agentRequiresApproval(p, "bot-x", "repo:read", null)).toBe(false);
  });
  test("no match for an unlisted agent", () => {
    const p = compiled({ "bot-x": ["*:write"] });
    expect(agentRequiresApproval(p, "bot-y", "repo:write", null)).toBe(false);
  });
  test("empty overlay never matches", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "h", grants: [] });
    if (!r.ok) throw new Error("compile failed");
    expect(agentRequiresApproval(r.policy, "bot-x", "repo:write", null)).toBe(false);
  });
  test("scoped rule matches only a matching target", () => {
    const p = compiled({ "bot-x": [{ action: "pr:merge", targets: ["/repos/acme/*"] }] });
    expect(agentRequiresApproval(p, "bot-x", "pr:merge", "/repos/acme/web")).toBe(true);
    expect(agentRequiresApproval(p, "bot-x", "pr:merge", "/repos/other/web")).toBe(false);
  });
  test("scoped rule: a null target matches (fail-closed for friction)", () => {
    const p = compiled({ "bot-x": [{ action: "pr:merge", targets: ["/repos/acme/*"] }] });
    expect(agentRequiresApproval(p, "bot-x", "pr:merge", null)).toBe(true);
  });
});

describe("case-insensitive escalation targets", () => {
  const base = { agent: "a", on_behalf_of: "h" };

  test("compileGlob: default is case-sensitive; caseInsensitive=true folds case", () => {
    expect(compileGlob("/repos/acme/*").test("/repos/ACME/x")).toBe(false);
    expect(compileGlob("/repos/acme/*", true).test("/repos/ACME/x")).toBe(true);
  });

  const grantTargetRe = (clause: "deny" | "require_approval" | "allow") => {
    const grant: Record<string, unknown> = { tool: "github" };
    grant[clause] = [{ action: "pr:merge", targets: ["/repos/acme/*"] }];
    if (clause !== "allow") grant.allow = ["repo:read"];
    const r = compilePolicyObject({ ...base, grants: [grant] });
    if (!r.ok) throw new Error(r.error);
    const g = r.policy.grants.get("github")!;
    const rules = clause === "deny" ? g.deny : clause === "require_approval" ? g.requireApproval : g.allow;
    return rules[0]!.targets![0]!.re;
  };

  test("grant deny target matches a mis-cased request (bypass closed)", () => {
    expect(grantTargetRe("deny").test("/repos/ACME/x")).toBe(true);
    expect(grantTargetRe("deny").test("/repos/acme/x")).toBe(true);
  });
  test("grant require_approval target is case-insensitive", () => {
    expect(grantTargetRe("require_approval").test("/repos/ACME/x")).toBe(true);
  });
  test("grant allow target stays case-sensitive (no over-allow)", () => {
    expect(grantTargetRe("allow").test("/repos/ACME/x")).toBe(false);
    expect(grantTargetRe("allow").test("/repos/acme/x")).toBe(true);
  });

  test("per-agent approval overlay target is case-insensitive", () => {
    const r = compilePolicyObject({
      ...base,
      grants: [],
      approvals: { per_agent: { "bot-x": [{ action: "pr:merge", targets: ["/repos/acme/*"] }] } },
    });
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.perAgentApproval.get("bot-x")![0]!.targets![0]!.re.test("/repos/ACME/x")).toBe(true);
  });

  test("tripwire target is case-insensitive", () => {
    const r = compilePolicyObject({
      ...base,
      grants: [],
      tripwires: [{ action: "repo:delete", targets: ["/repos/acme/*"] }],
    });
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.tripwires[0]!.targets![0]!.re.test("/repos/ACME/x")).toBe(true);
  });

  test("response-cap target is case-insensitive", () => {
    const r = compilePolicyObject({
      ...base,
      grants: [],
      responses: [{ on: ["repo:read"], targets: ["/repos/acme/*"], max_bytes: 1000, on_exceed: "truncate" }],
    });
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.responses[0]!.targets![0]!.re.test("/repos/ACME/x")).toBe(true);
  });

  test("action globs stay case-sensitive (deny action)", () => {
    const r = compilePolicyObject({
      ...base,
      grants: [{ tool: "github", allow: ["repo:read"], deny: [{ action: "pr:merge", targets: ["/x"] }] }],
    });
    if (!r.ok) throw new Error(r.error);
    const action = r.policy.grants.get("github")!.deny[0]!.action.re;
    expect(action.test("PR:MERGE")).toBe(false);
    expect(action.test("pr:merge")).toBe(true);
  });
});
