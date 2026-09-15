import { test, expect, describe } from "bun:test";
import { agentSchema } from "../src/config/schema.ts";

const base = { id: "a", token_hash: "a".repeat(64) };

describe("agent targets", () => {
  test("absent → targets undefined (unrestricted, back-compat)", () => {
    const parsed = agentSchema.parse(base);
    expect(parsed.targets).toBeUndefined();
  });
  test("a list of globs parses through", () => {
    const parsed = agentSchema.parse({ ...base, targets: ["/repos/acme/*", "/repos/team/app"] });
    expect(parsed.targets).toEqual(["/repos/acme/*", "/repos/team/app"]);
  });
  test("an empty list is rejected (min 1 — an unset scope is `absent`, not `[]`)", () => {
    expect(() => agentSchema.parse({ ...base, targets: [] })).toThrow();
  });
  test("an empty-string glob is rejected", () => {
    expect(() => agentSchema.parse({ ...base, targets: [""] })).toThrow();
  });
  test("more than 100 globs is rejected (the same cap a sub-token answers to)", () => {
    const many = Array.from({ length: 101 }, (_, i) => `/repos/o${i}/*`);
    expect(() => agentSchema.parse({ ...base, targets: many })).toThrow();
  });
  test("a decoy with targets is rejected (a decoy trips before scope is evaluated)", () => {
    expect(() => agentSchema.parse({ ...base, decoy: true, targets: ["/repos/acme/*"] })).toThrow(/decoy/i);
  });
  test("a decoy without targets still parses", () => {
    expect(agentSchema.parse({ ...base, decoy: true })).toMatchObject({ decoy: true });
  });
});

describe("agent actions", () => {
  test("absent → actions undefined (unrestricted, back-compat)", () => {
    expect(agentSchema.parse(base).actions).toBeUndefined();
  });
  test("a list of action globs parses through", () => {
    const parsed = agentSchema.parse({ ...base, actions: ["repo:read", "pr:*"] });
    expect(parsed.actions).toEqual(["repo:read", "pr:*"]);
  });
  test("actions and targets coexist (both axes)", () => {
    const parsed = agentSchema.parse({ ...base, actions: ["repo:read"], targets: ["/repos/acme/*"] });
    expect(parsed.actions).toEqual(["repo:read"]);
    expect(parsed.targets).toEqual(["/repos/acme/*"]);
  });
  test("an empty list is rejected (min 1 — unset is `absent`, not `[]`)", () => {
    expect(() => agentSchema.parse({ ...base, actions: [] })).toThrow();
  });
  test("more than 100 globs is rejected", () => {
    const many = Array.from({ length: 101 }, (_, i) => `act:${i}`);
    expect(() => agentSchema.parse({ ...base, actions: many })).toThrow();
  });
  test("a decoy with actions is rejected", () => {
    expect(() => agentSchema.parse({ ...base, decoy: true, actions: ["repo:read"] })).toThrow(/decoy/i);
  });
});
