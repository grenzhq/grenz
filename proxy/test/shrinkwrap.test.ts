import { test, expect, describe } from "bun:test";
import { policySchema, type PolicySource } from "../src/policy/schema.ts";
import { shrinkwrapPolicy } from "../src/policy/shrinkwrap.ts";
import { stringify as stringifyYaml } from "yaml";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { evaluate } from "../src/policy/evaluate.ts";

function src(): PolicySource {
  return policySchema.parse({
    agent: "claude-code",
    on_behalf_of: "x",
    grants: [
      { tool: "github", allow: ["repo:*", "issue:*"], deny: ["repo:delete"], require_approval: ["pr:merge"] },
      { tool: "linear", allow: ["issue:read", "issue:update"] },
    ],
    budget: { max_actions_per_hour: 100 },
  });
}

describe("shrinkwrapPolicy", () => {
  test("tightens allow to used actions; preserves deny/require_approval/budget", () => {
    const used = new Map([
      ["github", new Set(["repo:read", "issue:create"])],
      ["linear", new Set(["issue:read"])],
    ]);
    const out = shrinkwrapPolicy(src(), used);
    const gh = out.grants.find((g) => g.tool === "github")!;
    expect(gh.allow).toEqual(["issue:create", "repo:read"]); // sorted, used-only
    expect(gh.deny).toEqual(["repo:delete"]);
    expect(gh.require_approval).toEqual(["pr:merge"]);
    const lin = out.grants.find((g) => g.tool === "linear")!;
    expect(lin.allow).toEqual(["issue:read"]);
    expect(out.budget).toEqual({ max_actions_per_hour: 100 });
  });

  test("a tool with no used actions -> allow: []", () => {
    const out = shrinkwrapPolicy(src(), new Map([["github", new Set(["repo:read"])]]));
    expect(out.grants.find((g) => g.tool === "linear")!.allow).toEqual([]);
  });

  test("does not mutate the input source", () => {
    const s = src();
    shrinkwrapPolicy(s, new Map([["github", new Set(["repo:read"])]]));
    expect(s.grants.find((g) => g.tool === "github")!.allow).toEqual(["repo:*", "issue:*"]);
  });

  test("shrinkwrapped policy recompiles and still permits every used action", () => {
    const used = new Map([["github", new Set(["repo:read", "issue:create"])]]);
    const out = shrinkwrapPolicy(src(), used);
    const r = compilePolicyYaml(stringifyYaml(out));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    for (const a of ["repo:read", "issue:create"]) {
      expect(evaluate(r.policy, { tool: "github", action: a, target: null }).decision).not.toBe("deny");
    }
  });
});
