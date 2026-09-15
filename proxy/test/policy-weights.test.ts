import { test, expect, describe } from "bun:test";
import { compilePolicyObject } from "../src/policy/compile.ts";
import { actionCost } from "../src/policy/evaluate.ts";

function policyWith(weights: Record<string, number>) {
  const r = compilePolicyObject({
    agent: "a",
    on_behalf_of: "b",
    grants: [],
    budget: { max_actions_per_hour: 100, weights },
  });
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

describe("actionCost", () => {
  test("no weights -> every action costs 1", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    if (!r.ok) throw new Error(r.error);
    expect(actionCost(r.policy, "pr:merge")).toBe(1);
  });
  test("unmatched action costs 1", () => {
    const p = policyWith({ "repo:delete": 25 });
    expect(actionCost(p, "repo:read")).toBe(1);
  });
  test("single match uses its weight", () => {
    const p = policyWith({ "pr:merge": 10 });
    expect(actionCost(p, "pr:merge")).toBe(10);
  });
  test("multiple matches -> max-wins", () => {
    const p = policyWith({ "pr:*": 5, "pr:merge": 10 });
    expect(actionCost(p, "pr:merge")).toBe(10);
    expect(actionCost(p, "pr:create")).toBe(5);
  });
  test("a broad high weight still max-wins over a specific low one", () => {
    const p = policyWith({ "pr:*": 10, "pr:merge": 5 });
    expect(actionCost(p, "pr:merge")).toBe(10);
  });
});

describe("budget.weights (compile)", () => {
  test("compiles to budgetWeights", () => {
    const p = policyWith({ "repo:delete": 25, "pr:*": 5 });
    expect(p.budgetWeights.length).toBe(2);
  });
  test("absent -> empty", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.budgetWeights).toHaveLength(0);
  });
  test("zero weight rejected (fail closed)", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      budget: { weights: { "pr:merge": 0 } },
    });
    expect(r.ok).toBe(false);
  });
  test("non-integer weight rejected", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      budget: { weights: { "pr:merge": 1.5 } },
    });
    expect(r.ok).toBe(false);
  });
  test("absurd weight rejected (typo guard, > 1_000_000)", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      budget: { weights: { "pr:merge": 10_000_000 } },
    });
    expect(r.ok).toBe(false);
  });
});
