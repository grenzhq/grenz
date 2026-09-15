import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { resolveResponseLimit } from "../src/response/limit.ts";

function policy(responsesYaml: string): CompiledPolicy {
  const c = compilePolicyYaml(
    `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]\n${responsesYaml}`,
  );
  if (!c.ok) throw new Error(c.error);
  return c.policy;
}

describe("resolveResponseLimit", () => {
  test("no matching rule -> null (uncapped)", () => {
    const p = policy(`responses:\n  - on: [pr:read]\n    max_bytes: 100\n`);
    expect(resolveResponseLimit(p, "repo:read", "o/r")).toBeNull();
  });

  test("matching action -> its cap", () => {
    const p = policy(`responses:\n  - on: [repo:read]\n    max_bytes: 100\n`);
    expect(resolveResponseLimit(p, "repo:read", "o/r")).toEqual({ maxBytes: 100, onExceed: "truncate" });
  });

  test("target scoping: rule with targets only matches in-scope targets", () => {
    const p = policy(`responses:\n  - on: [repo:read]\n    targets: ["secret/*"]\n    max_bytes: 50\n`);
    expect(resolveResponseLimit(p, "repo:read", "secret/x")).toEqual({ maxBytes: 50, onExceed: "truncate" });
    expect(resolveResponseLimit(p, "repo:read", "public/x")).toBeNull();
  });

  test("most-restrictive-wins: smallest max_bytes across overlapping rules", () => {
    const p = policy(
      `responses:\n  - on: ["repo:*"]\n    max_bytes: 1000\n  - on: [repo:read]\n    max_bytes: 200\n`,
    );
    expect(resolveResponseLimit(p, "repo:read", "o/r")).toEqual({ maxBytes: 200, onExceed: "truncate" });
  });

  test("tie on max_bytes -> deny beats truncate", () => {
    const p = policy(
      `responses:\n  - on: [repo:read]\n    max_bytes: 100\n    on_exceed: truncate\n  - on: [repo:read]\n    max_bytes: 100\n    on_exceed: deny\n`,
    );
    expect(resolveResponseLimit(p, "repo:read", "o/r")).toEqual({ maxBytes: 100, onExceed: "deny" });
  });

  test("null target = reachability: a targeted rule still matches (for explain/lint)", () => {
    const p = policy(`responses:\n  - on: [repo:read]\n    targets: ["secret/*"]\n    max_bytes: 50\n`);
    expect(resolveResponseLimit(p, "repo:read", null)).toEqual({ maxBytes: 50, onExceed: "truncate" });
  });
});
