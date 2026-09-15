import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { BreakGlassStore } from "../src/breakglass/store.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

const BOOT = "cadm-boot";
function policy() {
  const r = compilePolicyYaml(`agent: claude\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}
let dir: string, deps: ConsoleDeps, breakGlass: BreakGlassStore, pulled: unknown[];
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-cbg-"));
  const log = new RequestLog(join(dir, "r.db"));
  breakGlass = new BreakGlassStore(join(dir, "bg.json"));
  pulled = [];
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "claude", token_hash: await hashToken("t") }],
  });
  deps = {
    log,
    broker: null,
    revocations: null,
    delegations: null,
    grants: null,
    agentIds: ["claude"],
    adminToken: BOOT,
    tokenStore: new TokenStore(join(dir, "tok.json")),
    config,
    policy: policy(),
    canaryStore: null,
    breakGlass,
    notifier: { approvalRequested: async () => {}, breakGlassPulled: async (...a: unknown[]) => { pulled.push(a); } },
    now: () => 5000,
  } as unknown as ConsoleDeps;
});
afterEach(async () => {
  deps.log.close();
  await rm(dir, { recursive: true, force: true });
});

const req = (method: string, path: string, token = BOOT) =>
  handleConsole(
    new Request(`http://127.0.0.1${path}`, { method, headers: { "x-grenz-admin": token } }),
    new URL(`http://127.0.0.1${path}`),
    deps,
  );

describe("/console/break-glass", () => {
  test("POST pulls a window attributed to the admin token and fires the loud notice", async () => {
    const r = await req("POST", "/console/break-glass?agent=claude&actions=pr:merge&reason=hotfix&quorum=1&ttl=600");
    expect(r.status).toBe(200);
    const b = (await r.json()) as { id: string; pulled_by: string; quorum: number };
    expect(b.pulled_by).toBe("bootstrap"); // the authenticated admin identity
    expect(b.quorum).toBe(1);
    expect(breakGlass.list(5000)).toHaveLength(1);
    expect(pulled).toHaveLength(1);
  });

  test("POST unknown agent -> 404", async () => {
    expect((await req("POST", "/console/break-glass?agent=ghost&actions=pr:merge&reason=x")).status).toBe(404);
  });

  test("GET lists active windows", async () => {
    await req("POST", "/console/break-glass?agent=claude&actions=pr:merge&reason=x");
    const r = await req("GET", "/console/break-glass");
    const b = (await r.json()) as { windows: unknown[] };
    expect(b.windows).toHaveLength(1);
  });
});
