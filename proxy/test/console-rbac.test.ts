import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

const BOOTSTRAP = "cadm-bootstrap-xyz";

function policy() {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

let dir: string;
let deps: ConsoleDeps;
let tokenStore: TokenStore;
let viewerTok: string;
let approverTok: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-rbac-"));
  const log = new RequestLog(join(dir, "r.db"));
  const revocations = new RevocationStore(join(dir, "rev.json"));
  tokenStore = new TokenStore(join(dir, "admin-tokens.json"));
  viewerTok = (await tokenStore.create("vic", "viewer", 1000)).token;
  approverTok = (await tokenStore.create("amy", "approver", 1000)).token;
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "a", token_hash: await hashToken("t") }],
  });
  deps = {
    log,
    broker: null,
    revocations,
    delegations: null,
    grants: null,
    agentIds: ["a"],
    adminToken: BOOTSTRAP,
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

function call(method: string, path: string, token: string | null) {
  const headers: Record<string, string> = {};
  if (token) headers["x-grenz-admin"] = token;
  return handleConsole(
    new Request(`http://127.0.0.1${path}`, { method, headers }),
    new URL(`http://127.0.0.1${path}`),
    deps,
  );
}

describe("console RBAC", () => {
  test("no token -> 401", async () => {
    expect((await call("GET", "/console/summary", null)).status).toBe(401);
  });
  test("unknown token -> 401", async () => {
    expect((await call("GET", "/console/summary", "cadm-bogus")).status).toBe(401);
  });
  test("viewer reads but cannot mutate", async () => {
    expect((await call("GET", "/console/summary", viewerTok)).status).toBe(200);
    expect((await call("POST", "/console/revocations/a", viewerTok)).status).toBe(403);
    expect((await call("POST", "/console/approvals/x/approve", viewerTok)).status).toBe(403);
  });
  test("approver can hit approve route (approver-gated) but not revoke (admin)", async () => {
    // broker is null -> approve route returns 409, but crucially NOT 403 (role passed)
    expect((await call("POST", "/console/approvals/x/approve", approverTok)).status).toBe(409);
    expect((await call("POST", "/console/revocations/a", approverTok)).status).toBe(403);
  });
  test("bootstrap token is admin", async () => {
    expect((await call("POST", "/console/revocations/a", BOOTSTRAP)).status).toBe(200);
  });
});
