import { test, expect, describe } from "bun:test";
import { resolvePrincipal } from "../src/proxy/auth.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

const DAY = 86_400_000;
const NOW = 100 * DAY;

async function agents(expires_at?: string) {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {},
    agents: [{ id: "a", token_hash: await hashToken("tok"), ...(expires_at ? { expires_at } : {}) }],
  }).agents;
}
const iso = (ms: number) => new Date(ms).toISOString();

describe("resolvePrincipal expiry", () => {
  test("unexpired agent resolves; expiredAgentId null", async () => {
    const r = await resolvePrincipal(await agents(iso(NOW + DAY)), null, "tok", NOW);
    expect(r.principal).toEqual({ kind: "agent", agentId: "a", decoy: false, agentTargets: [], agentActions: [] });
    expect(r.expiredAgentId).toBeNull();
  });
  test("no-expiry agent resolves", async () => {
    const r = await resolvePrincipal(await agents(), null, "tok", NOW);
    expect(r.principal?.agentId).toBe("a");
  });
  test("expired agent → null principal, expiredAgentId set", async () => {
    const r = await resolvePrincipal(await agents(iso(NOW - DAY)), null, "tok", NOW);
    expect(r.principal).toBeNull();
    expect(r.expiredAgentId).toBe("a");
  });
  test("boundary: expiresAtMs === now is expired", async () => {
    const r = await resolvePrincipal(await agents(iso(NOW)), null, "tok", NOW);
    expect(r.principal).toBeNull();
    expect(r.expiredAgentId).toBe("a");
  });
  test("wrong token for an expired agent is a plain miss (no expiredAgentId)", async () => {
    const r = await resolvePrincipal(await agents(iso(NOW - DAY)), null, "wrong", NOW);
    expect(r.principal).toBeNull();
    expect(r.expiredAgentId).toBeNull();
  });
});
