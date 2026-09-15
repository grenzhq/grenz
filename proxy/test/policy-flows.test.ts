import { test, expect, describe } from "bun:test";
import { policySchema } from "../src/policy/schema.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";

const base = { agent: "a", on_behalf_of: "x" };

describe("flows schema", () => {
  test("accepts a flow with defaults applied", () => {
    const p = policySchema.parse({
      ...base,
      flows: [{ when: ["*:read"], then: ["chat:write"] }],
    });
    expect(p.flows![0]!.effect).toBe("require_approval");
    expect(p.flows![0]!.within_seconds).toBe(3600);
  });

  test("rejects empty when/then", () => {
    expect(() => policySchema.parse({ ...base, flows: [{ when: [], then: ["x"] }] })).toThrow();
    expect(() => policySchema.parse({ ...base, flows: [{ when: ["x"], then: [] }] })).toThrow();
  });

  test("rejects unknown key and out-of-range within_seconds", () => {
    expect(() =>
      policySchema.parse({ ...base, flows: [{ when: ["x"], then: ["y"], bogus: 1 }] }),
    ).toThrow();
    expect(() =>
      policySchema.parse({ ...base, flows: [{ when: ["x"], then: ["y"], within_seconds: 0 }] }),
    ).toThrow();
  });
});

describe("flows compile", () => {
  test("compiles patterns and converts within_seconds to ms", () => {
    const r = compilePolicyYaml(`
agent: a
on_behalf_of: x
flows:
  - when: ["*:read"]
    then: ["chat:write"]
    within_seconds: 60
`);
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.flows.length).toBe(1);
    const f = r.policy.flows[0]!;
    expect(f.withinMs).toBe(60_000);
    expect(f.effect).toBe("require_approval");
    expect(f.when[0]!.re.test("issue:read")).toBe(true);
    expect(f.then[0]!.re.test("chat:write")).toBe(true);
  });

  test("absent flows -> empty array", () => {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: x\n`);
    if (!r.ok) throw new Error(r.error);
    expect(r.policy.flows).toEqual([]);
  });
});
