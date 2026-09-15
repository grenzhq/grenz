import { test, expect, describe } from "bun:test";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { CanaryStore } from "../src/canary/store.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = "admin-token-canary";

function compile() {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

async function deps(canaryStore: CanaryStore | null): Promise<{ deps: ConsoleDeps; log: RequestLog }> {
  const dir = await mkdtemp(join(tmpdir(), "grenz-canary-ep-"));
  const log = new RequestLog(join(dir, "r.db"));
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "a", token_hash: await hashToken("t") }],
  });
  return {
    deps: {
      log,
      broker: null,
      revocations: null,
      delegations: null,
      grants: null,
      agentIds: ["a"],
      adminToken: ADMIN,
      config,
      policy: compile(),
      canaryStore,
      tokenStore: null,
      breakGlass: null,
      now: () => 1000,
    },
    log,
  };
}

function get(d: ConsoleDeps) {
  return handleConsole(
    new Request("http://127.0.0.1/console/canary", { headers: { "x-grenz-admin": ADMIN } }),
    new URL("http://127.0.0.1/console/canary"),
    d,
  );
}

describe("GET /console/canary", () => {
  test("returns the snapshot when a canary is configured", async () => {
    const store = new CanaryStore();
    store.observe("github", "repo:read", "allow", "deny");
    const { deps: d, log } = await deps(store);
    const res = await get(d);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { requests: number; divergences: number; rows: unknown[] };
    expect(body.requests).toBe(1);
    expect(body.divergences).toBe(1);
    expect(body.rows).toHaveLength(1);
    log.close();
  });

  test("returns { configured: false } when no canary is loaded", async () => {
    const { deps: d, log } = await deps(null);
    const res = await get(d);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ configured: false });
    log.close();
  });

  test("requires the admin token", async () => {
    const { deps: d, log } = await deps(new CanaryStore());
    const res = await handleConsole(
      new Request("http://127.0.0.1/console/canary"),
      new URL("http://127.0.0.1/console/canary"),
      d,
    );
    expect(res.status).toBe(401);
    log.close();
  });
});
