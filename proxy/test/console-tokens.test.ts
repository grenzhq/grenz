import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

const BOOT = "cadm-boot";
function policy() {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}
let dir: string, deps: ConsoleDeps, tokenStore: TokenStore;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-tk-"));
  const log = new RequestLog(join(dir, "r.db"));
  tokenStore = new TokenStore(join(dir, "admin-tokens.json"));
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "a", token_hash: await hashToken("t") }],
  });
  deps = {
    log,
    broker: null,
    revocations: null,
    delegations: null,
    grants: null,
    agentIds: ["a"],
    adminToken: BOOT,
    tokenStore,
    config,
    policy: policy(),
    canaryStore: null,
    breakGlass: null,
    now: () => 5000,
  } as ConsoleDeps;
});
afterEach(async () => {
  deps.log.close();
  await rm(dir, { recursive: true, force: true });
});

const req = (method: string, path: string, body?: unknown) =>
  handleConsole(
    new Request(`http://127.0.0.1${path}`, {
      method,
      headers: { "x-grenz-admin": BOOT, "content-type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    }),
    new URL(`http://127.0.0.1${path}`),
    deps,
  );

describe("/console/tokens", () => {
  test("POST creates and returns the plaintext once", async () => {
    const r = await req("POST", "/console/tokens", { name: "alice", role: "approver" });
    expect(r.status).toBe(200);
    const b = (await r.json()) as { name: string; role: string; token: string };
    expect(b.name).toBe("alice");
    expect(b.role).toBe("approver");
    expect(b.token).toMatch(/^grenz-adm_/);
    expect(tokenStore.resolve(await hashToken(b.token), 5000)).toEqual({ name: "alice", role: "approver", subject: null });
  });

  test("POST rejects a bad role (400)", async () => {
    expect((await req("POST", "/console/tokens", { name: "x", role: "superadmin" })).status).toBe(400);
  });

  test("POST rejects a missing name (400)", async () => {
    expect((await req("POST", "/console/tokens", { role: "viewer" })).status).toBe(400);
  });

  test("GET lists metadata without hashes or plaintext", async () => {
    await req("POST", "/console/tokens", { name: "alice", role: "viewer" });
    const r = await req("GET", "/console/tokens");
    const b = (await r.json()) as { tokens: Array<Record<string, unknown>> };
    expect(b.tokens[0]!.name).toBe("alice");
    expect(b.tokens[0]!.tokenHash).toBeUndefined();
    expect(b.tokens[0]!.token).toBeUndefined();
  });

  test("DELETE revokes", async () => {
    const c = (await (await req("POST", "/console/tokens", { name: "alice", role: "admin" })).json()) as { token: string };
    expect((await req("DELETE", "/console/tokens/alice")).status).toBe(200);
    expect(tokenStore.resolve(await hashToken(c.token), 6000)).toBeNull();
  });

  test("DELETE unknown -> 404", async () => {
    expect((await req("DELETE", "/console/tokens/ghost")).status).toBe(404);
  });
});
