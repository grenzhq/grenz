import { describe, expect, it } from "bun:test";
import { PolicyStore } from "./store.ts";
import { compilePolicyYaml, type CompiledPolicy } from "./compile.ts";

function compile(yaml: string): CompiledPolicy {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

const DEFAULT_YAML = `
agent: default
on_behalf_of: human
grants:
  - tool: github
    allow: ["pr:read"]
`;

const CI_YAML = `
agent: ci
on_behalf_of: human
grants:
  - tool: github
    allow: ["pr:merge"]
`;

const DENY_ALL_YAML = `
agent: default
on_behalf_of: human
grants: []
`;

function storeWithCi(): { store: PolicyStore; def: CompiledPolicy } {
  const def = compile(DEFAULT_YAML);
  const store = new PolicyStore(def, new Set(["ci"]), [{ name: "ci", policy: CI_YAML }]);
  return { store, def };
}

describe("PolicyStore.policyFor — resolution matrix", () => {
  it("undefined profile → default", () => {
    const { store, def } = storeWithCi();
    expect(store.policyFor(undefined)).toBe(def);
  });

  it("known profile → that merged profile", () => {
    const { store } = storeWithCi();
    expect(store.policyFor("ci")).not.toBeNull();
    expect([...store.policyFor("ci")!.grants.keys()]).toContain("github");
  });

  it("unknown profile → null", () => {
    const { store } = storeWithCi();
    expect(store.policyFor("ghost")).toBeNull();
  });

  it("closed → deny-all overrides a known profile", () => {
    const { store } = storeWithCi();
    const denyAll = compile(DENY_ALL_YAML);
    store.closeAll(denyAll);
    expect(store.policyFor("ci")).toBe(denyAll);
    expect(store.policyFor(undefined)).toBe(denyAll);
    expect(store.policyFor("ghost")).toBe(denyAll); // even an unknown name is denied, not null
  });

  it("reload reopens (clears closed), swaps the default, and re-derives profiles", () => {
    const { store } = storeWithCi();
    store.closeAll(compile(DENY_ALL_YAML));
    const outcome = store.reload(CI_YAML); // any valid policy reopens
    expect(outcome.ok).toBe(true);
    expect(store.policyFor("ci")).not.toBeNull(); // re-derived, still present
    expect(store.policyFor(undefined)).toBe(store.defaultPolicy); // default swapped
  });

  it("current is an alias of defaultPolicy", () => {
    const { store, def } = storeWithCi();
    expect(store.current).toBe(def);
    expect(store.current).toBe(store.defaultPolicy);
  });

  it("profileNames lists the profiles", () => {
    const { store } = storeWithCi();
    expect([...store.profileNames]).toEqual(["ci"]);
  });

  it("a rejected reload keeps the live default and does NOT reopen a closed store", () => {
    const { store } = storeWithCi();
    const denyAll = compile(DENY_ALL_YAML);
    store.closeAll(denyAll);
    const outcome = store.reload("this: is not: valid: policy");
    expect(outcome.ok).toBe(false);
    expect(store.policyFor("ci")).toBe(denyAll); // still closed — a bad reload never reopens
  });

  it("isClosed tracks the stale-closed state (closeAll → true, successful reload → false)", () => {
    const { store } = storeWithCi();
    expect(store.isClosed).toBe(false);
    store.closeAll(compile(DENY_ALL_YAML));
    expect(store.isClosed).toBe(true);
    const outcome = store.reload(CI_YAML);
    expect(outcome.ok).toBe(true);
    expect(store.isClosed).toBe(false); // a successful reload reopens
  });

  it("isClosed stays true after a REJECTED reload (a bad reload never reopens)", () => {
    const { store } = storeWithCi();
    store.closeAll(compile(DENY_ALL_YAML));
    store.reload("this: is not: valid: policy");
    expect(store.isClosed).toBe(true);
  });
});

describe("PolicyStore — entries, declaredNames, atomic reload", () => {
  const declared = new Set(["ci"]);

  it("constructor throws on an undeclared or bad entry (fail-closed)", () => {
    expect(() => new PolicyStore(compile(DEFAULT_YAML), declared, [{ name: "nope", policy: CI_YAML }])).toThrow();
    expect(() =>
      new PolicyStore(compile(DEFAULT_YAML), declared, [{ name: "ci", policy: "not: : yaml: [" }]),
    ).toThrow();
  });

  it("reload(def) keeps entries but re-derives over the NEW default", () => {
    const { store } = storeWithCi();
    const before = store.policyFor("ci");
    expect(store.reload("agent: default\non_behalf_of: human\ngrants: []\n").ok).toBe(true);
    const after = store.policyFor("ci");
    expect(after).not.toBeNull();
    expect(after).not.toBe(before); // re-derived over the new default
  });

  it("reload(def, entries) replaces; reload(def, []) clears", () => {
    const store = new PolicyStore(compile(DEFAULT_YAML), declared, []);
    expect(store.policyFor("ci")).toBeNull();
    expect(store.reload(DEFAULT_YAML, [{ name: "ci", policy: CI_YAML }]).ok).toBe(true);
    expect(store.policyFor("ci")).not.toBeNull();
    expect(store.reload(DEFAULT_YAML, []).ok).toBe(true);
    expect(store.policyFor("ci")).toBeNull();
  });

  it("a declared name the bundle omits → deny (agent_policy_unresolved via null)", () => {
    const store = new PolicyStore(compile(DEFAULT_YAML), new Set(["ci", "deploy"]), [
      { name: "ci", policy: CI_YAML },
    ]);
    expect(store.policyFor("ci")).not.toBeNull();
    expect(store.policyFor("deploy")).toBeNull(); // declared but not delivered → deny-by-default
  });

  it("reload with an undeclared/bad entry → !ok, def AND profiles unchanged (keep-current)", () => {
    const { store } = storeWithCi();
    expect(store.reload(DEFAULT_YAML, [{ name: "nope", policy: CI_YAML }]).ok).toBe(false);
    expect(store.policyFor("ci")).not.toBeNull();
    expect(store.reload(DEFAULT_YAML, [{ name: "ci", policy: "not: : yaml: [" }]).ok).toBe(false);
    expect(store.policyFor("ci")).not.toBeNull();
  });
});
