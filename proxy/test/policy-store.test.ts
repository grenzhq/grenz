import { test, expect, describe } from "bun:test";
import { PolicyStore } from "../src/policy/store.ts";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";

function compile(yaml: string): CompiledPolicy {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

const ONE_GRANT = `
agent: claude-code
on_behalf_of: a@b.dev
grants:
  - tool: github
    allow: [repo:read]
`;

const TWO_GRANTS = `
agent: claude-code
on_behalf_of: a@b.dev
grants:
  - tool: github
    allow: [repo:read, pr:create]
  - tool: mcp
    allow: ["tools:list"]
`;

describe("PolicyStore", () => {
  test("current returns the initial policy", () => {
    const store = new PolicyStore(compile(ONE_GRANT));
    expect(store.current.grants.size).toBe(1);
  });

  test("reload swaps current on a valid policy and reports grant counts", () => {
    const store = new PolicyStore(compile(ONE_GRANT));
    const outcome = store.reload(TWO_GRANTS);
    expect(outcome).toEqual({ ok: true, grants: 2, previousGrants: 1 });
    expect(store.current.grants.size).toBe(2);
    expect(store.current.grants.has("mcp")).toBe(true);
  });

  test("reload REJECTS malformed YAML and keeps the current policy", () => {
    const store = new PolicyStore(compile(ONE_GRANT));
    const outcome = store.reload("agent: : :\n  - broken");
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error).toContain("malformed policy");
    expect(store.current.grants.size).toBe(1); // unchanged — old policy still live
  });

  test("reload REJECTS an unknown-key policy and keeps the current policy", () => {
    const store = new PolicyStore(compile(TWO_GRANTS));
    const outcome = store.reload("agent: a\non_behalf_of: b\ngrants: []\nsurprise: true\n");
    expect(outcome.ok).toBe(false);
    expect(store.current.grants.size).toBe(2); // unchanged
  });
});
