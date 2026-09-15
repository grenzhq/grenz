import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { ApprovalBroker } from "../src/approvals/broker.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";

function policy() {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

let dir: string;
let deps: ConsoleDeps;
let broker: ApprovalBroker;
let tokA: string;
let tokB: string;
let tokenStore: TokenStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-q-"));
  const log = new RequestLog(join(dir, "r.db"));
  tokenStore = new TokenStore(join(dir, "admin-tokens.json"));
  tokA = (await tokenStore.create("amy", "approver", 1000)).token;
  tokB = (await tokenStore.create("bob", "approver", 1000)).token;
  broker = new ApprovalBroker(300_000, 1000, () => 5000); // (ttlMs, maxPending, clock)
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "a", token_hash: await hashToken("t") }],
  });
  deps = {
    log,
    broker,
    revocations: null,
    delegations: null,
    grants: null,
    agentIds: ["a"],
    adminToken: "cadm-boot",
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

function approve(id: string, token: string, bodyBy?: string) {
  return handleConsole(
    new Request(`http://127.0.0.1/console/approvals/${id}/approve`, {
      method: "POST",
      headers: { "x-grenz-admin": token, "content-type": "application/json" },
      body: JSON.stringify(bodyBy ? { by: bodyBy } : {}),
    }),
    new URL(`http://127.0.0.1/console/approvals/${id}/approve`),
    deps,
  );
}

const INPUT = { agentId: "a", upstream: "github", tool: "github", action: "repo:read", target: "/x", method: "GET" };

describe("quorum enforced by distinct authenticated tokens", () => {
  test("two DISTINCT tokens settle quorum 2; the SAME token twice does not", async () => {
    const { id } = broker.create(INPUT, 2);
    let r = await approve(id, tokA);
    let b = (await r.json()) as { by: string; satisfied: boolean; approvals: number };
    expect(b.by).toBe("amy");
    expect(b.satisfied).toBe(false);
    r = await approve(id, tokA); // same token again
    b = (await r.json()) as { by: string; satisfied: boolean; approvals: number };
    expect(b.approvals).toBe(1);
    expect(b.satisfied).toBe(false);
    r = await approve(id, tokB); // distinct token
    b = (await r.json()) as { by: string; satisfied: boolean; approvals: number };
    expect(b.by).toBe("bob");
    expect(b.satisfied).toBe(true);
  });

  test("a client-supplied `by` in the body is IGNORED (server-derived identity wins)", async () => {
    const { id } = broker.create(INPUT, 2);
    const r = await approve(id, tokA, "bob"); // amy's token claiming to be "bob"
    const b = (await r.json()) as { by: string };
    expect(b.by).toBe("amy"); // NOT "bob"
  });
});
