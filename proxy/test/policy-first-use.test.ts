import { test, expect, describe } from "bun:test";
import { compilePolicyObject, type CompiledFirstUse } from "../src/policy/compile.ts";
import { firstUseInScope } from "../src/policy/first-use.ts";

function firstUse(over: {
  on_first?: "deny" | "require_approval";
  only?: string[];
  window_seconds?: number;
}): CompiledFirstUse {
  const r = compilePolicyObject({
    agent: "a",
    on_behalf_of: "b",
    grants: [],
    first_use: {
      only: over.only ?? ["*:delete", "pr:merge"],
      ...(over.on_first ? { on_first: over.on_first } : {}),
      ...(over.window_seconds ? { window_seconds: over.window_seconds } : {}),
    },
  });
  if (!r.ok) throw new Error(r.error);
  if (r.policy.firstUse === null) throw new Error("first_use did not compile");
  return r.policy.firstUse;
}

describe("firstUseInScope", () => {
  test("matches only actions in the `only` list", () => {
    const fu = firstUse({ only: ["pr:*", "repo:delete"] });
    expect(firstUseInScope(fu, "pr:merge")).toBe(true);
    expect(firstUseInScope(fu, "repo:delete")).toBe(true);
    expect(firstUseInScope(fu, "repo:read")).toBe(false);
  });
  test("call:* matches a generic MCP tool call", () => {
    const fu = firstUse({ only: ["call:*"] });
    expect(firstUseInScope(fu, "call:delete_repo")).toBe(true);
    expect(firstUseInScope(fu, "session:end")).toBe(false);
  });
});

describe("first_use (compile)", () => {
  test("defaults: on_first require_approval, windowMs null", () => {
    const fu = firstUse({});
    expect(fu.onFirst).toBe("require_approval");
    expect(fu.windowMs).toBeNull();
    expect(fu.only.length).toBeGreaterThan(0);
  });
  test("window_seconds -> ms; on_first honored", () => {
    const fu = firstUse({ on_first: "deny", window_seconds: 3600 });
    expect(fu.onFirst).toBe("deny");
    expect(fu.windowMs).toBe(3_600_000);
  });
  test("absent block -> null", () => {
    const r = compilePolicyObject({ agent: "a", on_behalf_of: "b", grants: [] });
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.firstUse).toBeNull();
  });
  test("missing `only` rejected (fail closed)", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      first_use: { on_first: "deny" },
    });
    expect(r.ok).toBe(false);
  });
  test("empty `only` rejected (min 1)", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      first_use: { only: [] },
    });
    expect(r.ok).toBe(false);
  });
  test("malformed on_first rejected", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      first_use: { only: ["x"], on_first: "bogus" },
    });
    expect(r.ok).toBe(false);
  });
  test("unknown key rejected (strict)", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [],
      first_use: { only: ["x"], nope: 1 },
    });
    expect(r.ok).toBe(false);
  });
});
