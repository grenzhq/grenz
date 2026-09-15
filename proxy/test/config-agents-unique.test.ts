import { test, expect, describe } from "bun:test";
import { configSchema } from "../src/config/schema.ts";

/**
 * Agent identity is possession of a token, resolved by hashing the presented
 * token and matching against the configured hashes (auth.ts). Two agents that
 * share a `token_hash` are two identities behind one token: `resolvePrincipal`
 * would silently pick whichever the loop matched last, so per-agent budgets,
 * revocation, and first-use gating all attach to an arbitrary one. Two agents
 * that share an `id` are the same ambiguity for the human-meaningful unit. Both
 * are pathological config; reject at load (deny-by-default: refuse the
 * ambiguous input rather than resolve it unpredictably).
 */
const base = {
  listen: { host: "127.0.0.1", port: 8787 },
  upstreams: {},
};

describe("agents uniqueness", () => {
  test("distinct id + distinct hash parses", () => {
    const c = configSchema.parse({
      ...base,
      agents: [
        { id: "a", token_hash: "a".repeat(64) },
        { id: "b", token_hash: "b".repeat(64) },
      ],
    });
    expect(c.agents).toHaveLength(2);
  });

  test("duplicate token_hash is rejected at load", () => {
    expect(() =>
      configSchema.parse({
        ...base,
        agents: [
          { id: "a", token_hash: "a".repeat(64) },
          { id: "b", token_hash: "a".repeat(64) },
        ],
      }),
    ).toThrow(/token_hash/i);
  });

  test("duplicate id is rejected at load", () => {
    expect(() =>
      configSchema.parse({
        ...base,
        agents: [
          { id: "dup", token_hash: "a".repeat(64) },
          { id: "dup", token_hash: "b".repeat(64) },
        ],
      }),
    ).toThrow(/id/i);
  });

  test("single agent is unaffected", () => {
    const c = configSchema.parse({ ...base, agents: [{ id: "solo", token_hash: "c".repeat(64) }] });
    expect(c.agents).toHaveLength(1);
  });
});
