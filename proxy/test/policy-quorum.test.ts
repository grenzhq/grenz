import { test, expect, describe } from "bun:test";
import { compilePolicyObject } from "../src/policy/compile.ts";
import { approvalQuorum } from "../src/policy/evaluate.ts";

function policyWith(quorum: Record<string, number>) {
  const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], quorum });
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

describe("approvalQuorum", () => {
  test("no quorum block -> every action needs 1", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    if (!r.ok) throw new Error(r.error);
    expect(approvalQuorum(r.policy, "repo:delete")).toBe(1);
    expect(r.policy.quorums).toHaveLength(0);
  });
  test("unmatched action needs 1", () => {
    expect(approvalQuorum(policyWith({ "repo:delete": 2 }), "repo:read")).toBe(1);
  });
  test("a matching glob sets the quorum", () => {
    expect(approvalQuorum(policyWith({ "repo:delete": 2 }), "repo:delete")).toBe(2);
  });
  test("multiple matches -> the strictest (max) applies", () => {
    const p = policyWith({ "*:delete": 2, "repo:delete": 3 });
    expect(approvalQuorum(p, "repo:delete")).toBe(3);
    expect(approvalQuorum(p, "bucket:delete")).toBe(2);
  });
});

describe("quorum (compile + schema)", () => {
  test("compiles each entry to a CompiledQuorum", () => {
    const p = policyWith({ "repo:delete": 2, "*:delete": 3 });
    expect(p.quorums.length).toBe(2);
    expect(p.quorums.every((q) => typeof q.n === "number" && q.pattern.re instanceof RegExp)).toBe(true);
  });
  test("a quorum of 1 is rejected (1 is the default; min 2)", () => {
    expect(compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], quorum: { "repo:delete": 1 } }).ok).toBe(false);
  });
  test("a non-integer quorum is rejected", () => {
    expect(compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], quorum: { "repo:delete": 2.5 } }).ok).toBe(false);
  });
  test("an absurd quorum is rejected (max 16)", () => {
    expect(compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [], quorum: { "repo:delete": 99 } }).ok).toBe(false);
  });
});
