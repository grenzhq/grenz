import { test, expect, describe } from "bun:test";
import { compilePolicyObject } from "../src/policy/compile.ts";
import { diffPolicies, type DiffPair } from "../src/policy/diff.ts";

function policy(grants: Array<{ tool: string; allow?: string[]; deny?: string[]; require_approval?: string[] }>) {
  const compiled = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants });
  if (!compiled.ok) throw new Error(compiled.error);
  return compiled.policy;
}

describe("diffPolicies", () => {
  test("identical policies produce no diff entries", () => {
    const current = policy([{ tool: "github", allow: ["repo:read", "pr:create"] }]);
    const candidate = policy([{ tool: "github", allow: ["repo:read", "pr:create"] }]);
    const pairs: DiffPair[] = [
      { tool: "github", action: "repo:read" },
      { tool: "github", action: "pr:create" },
      { tool: "github", action: "pr:merge" },
    ];
    expect(diffPolicies(current, candidate, pairs)).toEqual([]);
  });

  test("an added deny flips a previously-allowed pair from allow to deny", () => {
    const current = policy([{ tool: "github", allow: ["repo:read", "pr:merge"] }]);
    const candidate = policy([{ tool: "github", allow: ["repo:read", "pr:merge"], deny: ["pr:merge"] }]);
    const pairs: DiffPair[] = [
      { tool: "github", action: "repo:read" },
      { tool: "github", action: "pr:merge" },
    ];
    expect(diffPolicies(current, candidate, pairs)).toEqual([
      { tool: "github", action: "pr:merge", from: "allow", to: "deny" },
    ]);
  });

  test("a widened allow flips a previously-denied pair from deny to allow", () => {
    const current = policy([{ tool: "github", allow: ["repo:read"] }]); // pr:merge -> deny (no_matching_allow)
    const candidate = policy([{ tool: "github", allow: ["repo:read", "pr:merge"] }]);
    const pairs: DiffPair[] = [{ tool: "github", action: "pr:merge" }];
    expect(diffPolicies(current, candidate, pairs)).toEqual([
      { tool: "github", action: "pr:merge", from: "deny", to: "allow" },
    ]);
  });

  test("same decision reached via a different matched pattern is not reported", () => {
    const current = policy([{ tool: "github", allow: ["repo:*"] }]);
    const candidate = policy([{ tool: "github", allow: ["repo:read", "repo:write", "repo:delete"] }]);
    const pairs: DiffPair[] = [{ tool: "github", action: "repo:read" }];
    expect(diffPolicies(current, candidate, pairs)).toEqual([]);
  });

  test("empty pairs list produces an empty diff", () => {
    const current = policy([{ tool: "github", allow: ["repo:read"] }]);
    const candidate = policy([{ tool: "github", allow: [] }]);
    expect(diffPolicies(current, candidate, [])).toEqual([]);
  });

  test("pure — same input, same output", () => {
    const current = policy([{ tool: "github", allow: ["repo:read"] }]);
    const candidate = policy([{ tool: "github", allow: [] }]);
    const pairs: DiffPair[] = [{ tool: "github", action: "repo:read" }];
    expect(diffPolicies(current, candidate, pairs)).toEqual(diffPolicies(current, candidate, pairs));
  });

  test("adding a target-scoped allow surfaces as a change (reachability)", () => {
    const before = policy([{ tool: "github", allow: ["repo:read"] }]);
    const afterCompiled = compilePolicyObject({
      agent: "a", on_behalf_of: "b",
      grants: [{
        tool: "github",
        allow: ["repo:read", { action: "pr:*", targets: ["/repos/acme/*"] }],
      }],
    });
    if (!afterCompiled.ok) throw new Error(afterCompiled.error);
    const entries = diffPolicies(before, afterCompiled.policy, [{ tool: "github", action: "pr:create" }]);
    expect(entries).toEqual([{ tool: "github", action: "pr:create", from: "deny", to: "allow" }]);
  });
});
