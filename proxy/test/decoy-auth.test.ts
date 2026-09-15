import { test, expect, describe } from "bun:test";
import { resolvePrincipal } from "../src/proxy/auth.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

async function agents(decoy: boolean) {
  const cfg = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {},
    agents: [
      { id: "real", token_hash: await hashToken("real-tok") },
      { id: "trap", token_hash: await hashToken("trap-tok"), decoy },
    ],
  });
  return cfg.agents;
}

describe("resolvePrincipal decoy flag", () => {
  test("a decoy agent resolves as kind=agent with decoy=true", async () => {
    const r = await resolvePrincipal(await agents(true), null, "trap-tok", 0);
    expect(r.principal).toEqual({ kind: "agent", agentId: "trap", decoy: true, agentTargets: [], agentActions: [] });
  });

  test("a real agent resolves with decoy=false", async () => {
    const r = await resolvePrincipal(await agents(true), null, "real-tok", 0);
    expect(r.principal).toEqual({ kind: "agent", agentId: "real", decoy: false, agentTargets: [], agentActions: [] });
  });

  test("decoy defaults to false when the field is absent", async () => {
    const r = await resolvePrincipal(await agents(false), null, "trap-tok", 0);
    expect(r.principal).toEqual({ kind: "agent", agentId: "trap", decoy: false, agentTargets: [], agentActions: [] });
  });

  test("an unknown token is a miss", async () => {
    const r = await resolvePrincipal(await agents(true), null, "nope", 0);
    expect(r.principal).toBeNull();
  });
});
