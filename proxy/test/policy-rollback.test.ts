import { test, expect, describe } from "bun:test";
import { planRollback } from "../src/policy/rollback.ts";

const GH = (extra: string) => `
agent: a
on_behalf_of: b
grants:
  - tool: github
    allow: [repo:read${extra}]
`;

describe("planRollback", () => {
  test("refuses a candidate that will not compile", () => {
    const plan = planRollback(GH(""), "not: [valid: yaml", []);
    expect(plan.ok).toBe(false);
  });

  test("proceeds when candidate compiles; diff over pairs reflects the change", () => {
    // current allows pr:merge; candidate (rollback target) does not
    const current = GH(", pr:merge");
    const candidate = GH("");
    const plan = planRollback(current, candidate, [{ tool: "github", action: "pr:merge" }]);
    expect(plan.ok).toBe(true);
    if (plan.ok) {
      expect(plan.currentCompiles).toBe(true);
      expect(plan.diff).toEqual([{ tool: "github", action: "pr:merge", from: "allow", to: "deny" }]);
    }
  });

  test("proceeds even when the CURRENT policy is broken (nothing to diff)", () => {
    const plan = planRollback("garbage: [", GH(""), [{ tool: "github", action: "repo:read" }]);
    expect(plan.ok).toBe(true);
    if (plan.ok) {
      expect(plan.currentCompiles).toBe(false);
      expect(plan.diff).toEqual([]);
    }
  });

  test("no pairs -> empty diff but still proceedable", () => {
    const plan = planRollback(GH(", pr:merge"), GH(""), []);
    expect(plan.ok).toBe(true);
    if (plan.ok) expect(plan.diff).toEqual([]);
  });
});
