/**
 * A delegation is only ever an ATTENUATION of its root agent. If the root agent
 * is gone from config — deleted, or past its `expires_at` — there is nothing
 * left to attenuate from, so the sub-token resolves to no principal.
 *
 * Regression: the root's scope used to be read live with a `?? []` fallback, and
 * `[]` means "unrestricted". Deleting a scoped agent from grenz.yaml therefore
 * WIDENED its live sub-tokens instead of killing them — a scoped agent's
 * children became unscoped the moment the parent was removed. The `policyProfile`
 * beside it was already snapshotted at mint for exactly this reason; the two
 * scope axes were not.
 */
import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolvePrincipal } from "../src/proxy/auth.ts";
import { configSchema, type AgentConfig } from "../src/config/schema.ts";
import { DelegationStore } from "../src/delegate/store.ts";
import { hashToken } from "../src/util/token.ts";

const NOW = 1_000_000_000;
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

async function agentSet(over?: { expires_at?: string }): Promise<readonly AgentConfig[]> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {},
    agents: [
      {
        id: "root",
        token_hash: await hashToken("root-tok"),
        targets: ["/repos/acme/*"],
        actions: ["repo:read"],
        ...(over?.expires_at ? { expires_at: over.expires_at } : {}),
      },
    ],
  }).agents;
}

let tmp: string;
let delegations: DelegationStore;
let childToken: string;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-orphan-"));
  delegations = new DelegationStore(join(tmp, "delegations.json"));
  const minted = await delegations.mint({
    parentAgentId: "root",
    actions: ["repo:read"],
    ttlMs: 900_000,
    note: "child",
    now: NOW,
  });
  childToken = minted.token;
});
afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe("delegation with a live root agent", () => {
  test("resolves, and inherits the root's own scope on BOTH axes", async () => {
    const r = await resolvePrincipal(await agentSet(), delegations, childToken, NOW);
    expect(r.principal).toMatchObject({
      kind: "delegation",
      agentId: "root",
      agentTargets: ["/repos/acme/*"],
      agentActions: ["repo:read"],
    });
    expect(r.orphanRootAgentId).toBeNull();
  });
});

describe("delegation whose root agent is gone", () => {
  test("root deleted from config → NO principal (was: unrestricted scope)", async () => {
    const r = await resolvePrincipal([], delegations, childToken, NOW);
    expect(r.principal).toBeNull();
    expect(r.orphanRootAgentId).toBe("root");
  });

  test("root past its expires_at → NO principal", async () => {
    const r = await resolvePrincipal(await agentSet({ expires_at: iso(NOW - DAY) }), delegations, childToken, NOW);
    expect(r.principal).toBeNull();
    expect(r.orphanRootAgentId).toBe("root");
  });

  test("boundary: root expiring exactly at `now` is already gone", async () => {
    const r = await resolvePrincipal(await agentSet({ expires_at: iso(NOW) }), delegations, childToken, NOW);
    expect(r.principal).toBeNull();
    expect(r.orphanRootAgentId).toBe("root");
  });

  test("root unexpired at the boundary-1 still resolves", async () => {
    const r = await resolvePrincipal(await agentSet({ expires_at: iso(NOW + 1) }), delegations, childToken, NOW);
    expect(r.principal?.kind).toBe("delegation");
    expect(r.orphanRootAgentId).toBeNull();
  });

  test("an unknown token is a plain miss, not an orphan", async () => {
    const r = await resolvePrincipal(await agentSet(), delegations, "grenz_nope", NOW);
    expect(r.principal).toBeNull();
    expect(r.orphanRootAgentId).toBeNull();
  });
});
