import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";
import { DelegationStore } from "../src/delegate/store.ts";
import { GrantStore } from "../src/grant/store.ts";

const GITHUB_CRED = "ghp_paa_secret";
const MCP_CRED = "mcp_paa_secret";
let TOKEN: string;
let fake: ReturnType<typeof Bun.serve>;
let fakeUrl: string;

beforeAll(async () => {
  TOKEN = generateToken();
  fake = Bun.serve({
    port: 0,
    fetch: () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
  });
  fakeUrl = `http://127.0.0.1:${fake.port}`;
});
afterAll(() => fake.stop(true));

const vault: CredentialStore = {
  async get(k) {
    return k === "github_token" ? GITHUB_CRED : k === "mcp_token" ? MCP_CRED : undefined;
  },
  async keys() {
    return ["github_token", "mcp_token"];
  },
};

async function buildConfig(): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {
      github: { type: "github", base_url: fakeUrl, credential: "github_token" },
      mcp: { type: "mcp", base_url: fakeUrl, credential: "mcp_token" },
    },
    agents: [{ id: "claude-code", token_hash: await hashToken(TOKEN) }],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-paa-"));
});

async function makeHandler(policyYaml: string, opts?: { delegations?: DelegationStore; grants?: GrantStore }) {
  const compiled = compilePolicyYaml(policyYaml);
  if (!compiled.ok) throw new Error(compiled.error);
  const config = await buildConfig();
  const log = new RequestLog(join(tmp, "requests.db"));
  const handler = createHandler({ config, policy: compiled.policy, vault, log, delegations: opts?.delegations, grants: opts?.grants });
  return { handler, log };
}

function send(
  handler: (r: Request) => Promise<Response>,
  method: string,
  path: string,
  opts?: { body?: string; token?: string },
) {
  return handler(
    new Request(`http://grenz.local${path}`, {
      method,
      headers: { authorization: `Bearer ${opts?.token ?? TOKEN}` },
      body: opts?.body,
    }),
  );
}

const READ = ["GET", "/u/github/repos/o/r"] as const; // -> repo:read
const MERGE = ["PUT", "/u/github/repos/o/r/pulls/1/merge"] as const; // -> pr:merge

// Overlay clamps claude-code's pr:merge to require_approval, on top of a grant
// that otherwise ALLOWs it.
const CLAMP = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
`;

describe("per-agent approval overlay dispatch gate", () => {
  test("clamp fires: an allowed action escalates to approval (no broker -> approvals_unavailable)", async () => {
    const { handler, log } = await makeHandler(CLAMP);
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("never softens a deny: an explicit-deny action stays explicit_deny", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
`);
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("no overlay for the agent: unaffected, forwards normally", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
`);
    const res = await send(handler, ...MERGE);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("unlisted action: not clamped, forwards normally", async () => {
    const { handler, log } = await makeHandler(CLAMP);
    const res = await send(handler, ...READ); // repo:read is not in the overlay
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("MCP batch: one matching member escalates the whole batch", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["call:get_*", "call:delete_*"]
approvals:
  per_agent:
    claude-code: ["call:delete_*"]
`);
    // A 2-message batch: a benign get + a delete the overlay clamps. The
    // collapsed action is batch:2, but member gating must catch the delete.
    const batch = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_x" } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_y" } },
    ]);
    const res = await send(handler, "POST", "/u/mcp", { body: batch });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("delegation inherits its root agent's overlay (cannot escape via a sub-token)", async () => {
    const delegations = new DelegationStore(join(tmp, "del.json"));
    const { handler, log } = await makeHandler(CLAMP, { delegations });
    const { token: childToken } = await delegations.mint({
      parentAgentId: "claude-code",
      actions: ["pr:*"], // must COVER pr:merge or delegation_scope denies first
      ttlMs: 60_000,
      note: "",
      now: Date.now(),
    });
    const res = await send(handler, ...MERGE, { token: childToken });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("budget pre-gate still bites an escalated request (429 before queueing)", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
budget:
  per_agent:
    claude-code: 1
`);
    await send(handler, ...READ); // consumes the ceiling of 1 (allowed, forwards)
    const res = await send(handler, ...MERGE); // escalates -> pre-gate denies before approval
    expect(res.status).toBe(429);
    expect(res.headers.get("x-grenz-reason")).toBe("agent_budget_exceeded");
    log.close();
  });

  test("does NOT mask a first_use on_first:deny hard-deny (never softens a deny)", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: ["pr:merge"]
first_use:
  on_first: deny
  only: ["pr:merge"]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
`);
    // First-ever pr:merge: first_use would hard-deny. The overlay must run AFTER
    // first_use so it cannot clamp the hard deny into an approvable request.
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("first_use_denied");
    log.close();
  });

  test("clamps a jit_grant allow too (most-restrictive-wins, no jit exemption)", async () => {
    const grants = new GrantStore(join(tmp, "grants.json"));
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
approvals:
  per_agent:
    claude-code: ["pr:merge"]
`, { grants });
    // pr:merge is a policy GAP; the JIT grant widens it to allow(jit_grant),
    // then the overlay re-clamps it to require_approval.
    grants.mint({ agentId: "claude-code", actions: ["pr:merge"], ttlMs: 60_000, reason: "hotfix", now: Date.now() });
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("target-scoped: a matching request target escalates", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
approvals:
  per_agent:
    claude-code:
      - { action: "pr:merge", targets: ["/repos/o/*"] }
`);
    // MERGE target is /repos/o/r/pulls/1/merge — matches /repos/o/*
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("target-scoped: a non-matching request target forwards (no clamp)", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
approvals:
  per_agent:
    claude-code:
      - { action: "pr:merge", targets: ["/repos/acme/*"] }
`);
    // MERGE target /repos/o/... does not match /repos/acme/* — overlay does not fire
    const res = await send(handler, ...MERGE);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  // An MCP batch carries one target per message. The overlay matches those real
  // targets, so it fires on a batched member exactly as it would on the same
  // message sent alone — and stays quiet when none of them match.
  const BATCH_POLICY = (targets: string) => `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["call:get_*", "call:delete_*"]
approvals:
  per_agent:
    claude-code:
      - { action: "call:delete_*", targets: [${targets}] }
`;
  const BATCH_BODY = JSON.stringify([
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_x" } },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_y" } },
  ]);

  test("MCP batch: a target-scoped overlay fires on the batched member it matches", async () => {
    const { handler, log } = await makeHandler(BATCH_POLICY(`"tools/call delete_*"`));
    const res = await send(handler, "POST", "/u/mcp", { body: BATCH_BODY });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("MCP batch: an overlay matching no member's target does not clamp", async () => {
    const { handler, log } = await makeHandler(BATCH_POLICY(`"/never/matches"`));
    const res = await send(handler, "POST", "/u/mcp", { body: BATCH_BODY });
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });
});
