import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

/**
 * The bootstrap admin token must be matched the same way agent tokens are:
 * hash the presented value, then constant-time compare over equal-length hex
 * digests. A raw plaintext compare short-circuits on length, leaking the
 * bootstrap token's length as a timing side-channel. These tests pin the
 * observable contract (auth succeeds on the exact value; fails otherwise,
 * regardless of length) so the internal compare can stay hash-based.
 */
function policy() {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

let dir: string;
let deps: ConsoleDeps;
const BOOTSTRAP = "cadm-bootstrap-a-fairly-long-value-1234567890";

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-boot-"));
  const log = new RequestLog(join(dir, "r.db"));
  const revocations = new RevocationStore(join(dir, "rev.json"));
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
    tokenStore: null, // no RBAC store: only the bootstrap path is exercised
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

function call(token: string | null) {
  const headers: Record<string, string> = {};
  if (token) headers["x-grenz-admin"] = token;
  return handleConsole(
    new Request("http://127.0.0.1/console/summary", { method: "GET", headers }),
    new URL("http://127.0.0.1/console/summary"),
    deps,
  );
}

describe("bootstrap admin auth (hash-based)", () => {
  test("exact bootstrap value authenticates", async () => {
    expect((await call(BOOTSTRAP)).status).toBe(200);
  });

  test("a wrong token of the SAME length is rejected (compare is not length-gated)", async () => {
    const sameLen = "x".repeat(BOOTSTRAP.length);
    expect(sameLen.length).toBe(BOOTSTRAP.length);
    expect((await call(sameLen)).status).toBe(401);
  });

  test("a wrong token of a DIFFERENT length is rejected", async () => {
    expect((await call("short")).status).toBe(401);
  });

  test("no token is rejected", async () => {
    expect((await call(null)).status).toBe(401);
  });
});
