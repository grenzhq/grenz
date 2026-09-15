import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";
import { ApprovalBroker } from "../src/approvals/broker.ts";
import { ApprovalMemory } from "../src/approvals/memory.ts";
import type { Notifier } from "../src/notify/notifier.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { FleetRevocationStore } from "../src/revocation/store.ts";
import type { RevocationDistributionState } from "../src/revocation/types.ts";
import { DelegationStore } from "../src/delegate/store.ts";
import { GrantStore } from "../src/grant/store.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { PolicyStore } from "../src/policy/store.ts";
import type { PolicyDistributionState } from "../src/distribution/types.ts";

// --- Secrets that must never leak toward the agent or into the log ----------
const GITHUB_CRED = "ghp_REAL_github_secret_zzz111";
const MCP_CRED = "lin_REAL_mcp_secret_zzz222";
const UPSTREAM_BODY = JSON.stringify({ ok: true, note: "from upstream" });

let TOKEN: string;
let CI_TOKEN: string;
let fakeUrl: string;
let fake: ReturnType<typeof Bun.serve>;
let redirectTarget: ReturnType<typeof Bun.serve>;
let redirectTargetUrl: string;
let redirectHit: { count: number; auth: string | null };

// Captured by the fake upstream, reset per test.
let cap: { count: number; auth: string | null; ua: string | null; body: string; headers: Record<string, string> };

beforeAll(async () => {
  TOKEN = generateToken();
  CI_TOKEN = generateToken();
  fake = Bun.serve({
    port: 0,
    async fetch(req) {
      cap.count++;
      cap.auth = req.headers.get("authorization");
      cap.ua = req.headers.get("user-agent");
      cap.body = await req.text();
      cap.headers = {};
      for (const [k, v] of req.headers) cap.headers[k] = v;
      if (new URL(req.url).pathname.endsWith("/redirect")) {
        return new Response(null, { status: 302, headers: { location: `${redirectTargetUrl}/pwned` } });
      }
      return new Response(UPSTREAM_BODY, {
        status: 200,
        headers: { "content-type": "application/json", "set-cookie": "sess=upstream_cookie" },
      });
    },
  });
  redirectTarget = Bun.serve({
    port: 0,
    fetch(req) {
      redirectHit.count++;
      redirectHit.auth = req.headers.get("authorization");
      return new Response("target");
    },
  });
  redirectTargetUrl = `http://127.0.0.1:${redirectTarget.port}`;
  fakeUrl = `http://127.0.0.1:${fake.port}`;
});

afterAll(() => {
  fake.stop(true);
  redirectTarget.stop(true);
});

beforeEach(() => {
  cap = { count: 0, auth: null, ua: null, body: "", headers: {} };
  redirectHit = { count: 0, auth: null };
});

async function buildConfig(): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {
      github: { type: "github", base_url: fakeUrl, credential: "github_token" },
      mcp: { type: "mcp", base_url: fakeUrl, credential: "mcp_token" },
      // Points at a closed port so fetch() throws -> exercises the upstream_error path.
      deadgh: { type: "github", base_url: "http://127.0.0.1:1", credential: "github_token" },
      // Semantic adapter (Gate 3): Linear MCP tool names -> canonical actions.
      linear: { type: "linear", base_url: fakeUrl, credential: "mcp_token" },
    },
    agents: [
      { id: "claude-code", token_hash: await hashToken(TOKEN) },
      { id: "ci-bot", token_hash: await hashToken(CI_TOKEN) },
    ],
  });
}

const fullVault: CredentialStore = {
  async get(key) {
    if (key === "github_token") return GITHUB_CRED;
    if (key === "mcp_token") return MCP_CRED;
    return undefined;
  },
  async keys() {
    return ["github_token", "mcp_token"];
  },
};

const emptyVault: CredentialStore = {
  async get() {
    return undefined;
  },
  async keys() {
    return [];
  },
};

// Returns a present-but-empty credential — must be treated as missing.
const emptyStringVault: CredentialStore = {
  async get() {
    return "";
  },
  async keys() {
    return ["github_token"];
  },
};

const POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, pr:create, issue:read]
    deny: [pr:merge]
    require_approval: [issue:update]
  - tool: mcp
    allow: ["session:*", "tools:list", "call:get_*"]
  - tool: deadgh
    allow: [repo:read]
  - tool: linear
    allow: [issue:read]
    deny: [comment:delete]
`;

let tmp: string;
let dbPath: string;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-srv-"));
  dbPath = join(tmp, "requests.db");
});
// afterEach cleanup is best-effort (some dbs may be open); ignore failures.

interface Env {
  handler: (req: Request) => Promise<Response>;
  log: RequestLog;
  emitted: string[];
  broker?: ApprovalBroker;
}

async function makeEnv(opts?: {
  policy?: string;
  vault?: CredentialStore;
  now?: () => number;
  broker?: ApprovalBroker;
  approvalMemory?: ApprovalMemory;
  adminToken?: string;
  tokenStore?: TokenStore;
  notifier?: Notifier;
  revocations?: RevocationStore;
  delegations?: DelegationStore;
  grants?: GrantStore;
  shadow?: boolean;
  policyStore?: PolicyStore;
  policyDistribution?: PolicyDistributionState;
  fleetRevocations?: FleetRevocationStore;
  revocationDistribution?: RevocationDistributionState;
  config?: GrenzConfig;
}): Promise<Env> {
  const compiled = compilePolicyYaml(opts?.policy ?? POLICY);
  if (!compiled.ok) throw new Error(compiled.error);
  const config = opts?.config ?? (await buildConfig());
  const log = new RequestLog(dbPath);
  const emitted: string[] = [];
  const handler = createHandler({
    config,
    policy: compiled.policy,
    vault: opts?.vault ?? fullVault,
    log,
    now: opts?.now,
    broker: opts?.broker,
    approvalMemory: opts?.approvalMemory,
    adminToken: opts?.adminToken,
    tokenStore: opts?.tokenStore,
    notifier: opts?.notifier,
    revocations: opts?.revocations,
    delegations: opts?.delegations,
    grants: opts?.grants,
    shadow: opts?.shadow,
    policyStore: opts?.policyStore,
    policyDistribution: opts?.policyDistribution,
    fleetRevocations: opts?.fleetRevocations,
    revocationDistribution: opts?.revocationDistribution,
    emit: (l) => emitted.push(l),
  });
  return { handler, log, emitted, broker: opts?.broker };
}

/** A revocation store backed by a temp file inside the per-test dir. */
function makeRevocations(): RevocationStore {
  return new RevocationStore(join(tmp, "revocations.json"));
}

/** A delegation store backed by a temp file inside the per-test dir. */
function makeDelegations(): DelegationStore {
  return new DelegationStore(join(tmp, "delegations.json"));
}

/** A fleet-revocation store backed by a temp file inside the per-test dir. */
function makeFleet(agents: string[], version = 1): FleetRevocationStore {
  const s = new FleetRevocationStore(join(tmp, "fleet-revocations.json"));
  if (agents.length > 0 || version > 0) s.replace(agents, version, null, 1);
  return s;
}

/** A grant store backed by a temp file inside the per-test dir. */
function makeGrants(): GrantStore {
  return new GrantStore(join(tmp, "grants.json"));
}

async function waitForApproval(broker: ApprovalBroker, tries = 100): Promise<string> {
  for (let i = 0; i < tries; i++) {
    const list = broker.list();
    if (list.length > 0) return list[0]!.id;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error("no pending approval appeared");
}

function send(
  handler: Env["handler"],
  method: string,
  path: string,
  init?: { token?: string | null; body?: string },
): Promise<Response> {
  const headers: Record<string, string> = {};
  const token = init && "token" in init ? init.token : TOKEN;
  if (token) headers.authorization = `Bearer ${token}`;
  if (init?.body) headers["content-type"] = "application/json";
  return handler(new Request(`http://grenz.local${path}`, { method, headers, body: init?.body }));
}

function assertNoSecretIn(text: string): void {
  expect(text).not.toContain(GITHUB_CRED);
  expect(text).not.toContain(MCP_CRED);
  expect(text).not.toContain(TOKEN);
}

describe("proxy pipeline", () => {
  test("ALLOW: forwards, injects real credential, returns upstream body", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(await res.clone().text()).toBe(UPSTREAM_BODY);
    // Upstream saw the REAL credential...
    expect(cap.count).toBe(1);
    expect(cap.auth).toBe(`Bearer ${GITHUB_CRED}`);
    expect(cap.ua).toBe("grenz-proxy");
    // ...and never the GRENZ_TOKEN, in any header.
    for (const v of Object.values(cap.headers)) expect(v).not.toContain(TOKEN);
    // The agent's response carries no credential material, headers or body.
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    // An upstream session cookie must not be handed back to the agent.
    expect(res.headers.get("set-cookie")).toBeNull();
    const bodyText = await res.text();
    assertNoSecretIn(bodyText);
    for (const [, v] of res.headers) assertNoSecretIn(v);
    log.close();
  });

  test("DENY (explicit): pr:merge is blocked, upstream never called", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("DENY (default): unlisted action blocked", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "DELETE", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("no_matching_allow");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("DENY: a rule's remediation message surfaces as a hint", async () => {
    const policy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny:
      - action: pr:merge
        message: "open a PR and request review in #eng"
`;
    const { handler, log } = await makeEnv({ policy });
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    expect(res.headers.get("x-grenz-hint")).toBe("open a PR and request review in #eng");
    const body = (await res.json()) as { hint?: string };
    expect(body.hint).toBe("open a PR and request review in #eng");
    assertNoSecretIn(JSON.stringify(body));
    expect(cap.count).toBe(0);
    log.close();
  });

  test("DENY: a rule with no message emits no hint (regression)", async () => {
    const { handler, log } = await makeEnv(); // default POLICY denies pr:merge with no message
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-hint")).toBe(null);
    expect("hint" in ((await res.json()) as object)).toBe(false);
    log.close();
  });

  test("AUTH: invalid token -> 401, upstream never called", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/github/repos/o/r", { token: generateToken() });
    expect(res.status).toBe(401);
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("AUTH: missing token -> 401", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/github/repos/o/r", { token: null });
    expect(res.status).toBe(401);
    log.close();
  });

  test("unknown upstream -> 403 unknown_upstream", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/slack/whatever");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("unknown_upstream");
    log.close();
  });

  test("REQUIRE_APPROVAL: blocked at Gate 1 with approvals_unavailable", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "PATCH", "/u/github/repos/o/r/issues/5", { body: "{}" });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-decision")).toBe("require_approval");
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("credential missing -> 502, fail closed (never forwards without a credential)", async () => {
    const { handler, log } = await makeEnv({ vault: emptyVault });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(502);
    expect(res.headers.get("x-grenz-reason")).toBe("credential_missing");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("empty credential is treated as missing -> 502, never forwarded", async () => {
    const { handler, log } = await makeEnv({ vault: emptyStringVault });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(502);
    expect(res.headers.get("x-grenz-reason")).toBe("credential_missing");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("upstream error -> 502 upstream_error, honest log, not billed to budget", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/deadgh/repos/o/r");
    expect(res.status).toBe(502);
    expect(res.headers.get("x-grenz-reason")).toBe("upstream_error");
    // The response must NOT falsely claim the action succeeded.
    expect(res.headers.get("x-grenz-decision")).not.toBe("allow");
    // A never-forwarded action must not consume budget.
    expect(log.countAllowedSince("claude-code", 0)).toBe(0);
    log.close();
  });

  test("BUDGET: max_actions_per_hour enforced", async () => {
    const budgetPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 2
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: budgetPolicy, now: () => fixedNow });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    const third = await send(handler, "GET", "/u/github/repos/o/r");
    expect(third.status).toBe(429);
    expect(third.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    expect(cap.count).toBe(2); // only the two allowed calls reached upstream
    log.close();
  });

  test("SCHEDULE: closed window denies with schedule_closed (403)", async () => {
    const schedPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  timezone: UTC
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "17:00"
`;
    // 2024-07-14 is a Sunday -> closed.
    const sundayNoon = Date.UTC(2024, 6, 14, 12, 0);
    const { handler, log } = await makeEnv({ policy: schedPolicy, now: () => sundayNoon });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("schedule_closed");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("SCHEDULE: open window flows normally", async () => {
    const schedPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "17:00"
`;
    const tuesdayNoon = Date.UTC(2024, 6, 16, 12, 0); // Tue 12:00 UTC
    const { handler, log } = await makeEnv({ policy: schedPolicy, now: () => tuesdayNoon });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    log.close();
  });

  test("SCHEDULE: never overrides an explicit deny (keeps engine reason)", async () => {
    const schedPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny: [pr:merge]
schedule:
  windows:
    - days: [mon]
      start: "09:00"
      end: "17:00"
`;
    const sundayNoon = Date.UTC(2024, 6, 14, 12, 0); // closed
    const { handler, log } = await makeEnv({ policy: schedPolicy, now: () => sundayNoon });
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("SCHEDULE: on_closed require_approval routes through the broker", async () => {
    const schedPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  windows:
    - days: [mon]
      start: "09:00"
      end: "17:00"
  on_closed: require_approval
`;
    const sundayNoon = Date.UTC(2024, 6, 14, 12, 0); // closed
    const broker = new ApprovalBroker(60_000, 1000, () => sundayNoon);
    const { handler, log } = await makeEnv({ policy: schedPolicy, now: () => sundayNoon, broker });
    const inflight = send(handler, "GET", "/u/github/repos/o/r");
    broker.approve(await waitForApproval(broker), "ops");
    const res = await inflight;
    expect(res.status).toBe(200);
    log.close();
  });

  test("FIRST-USE: first occurrence requires approval, second flows", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
first_use:
  on_first: require_approval
  only: ["pr:*"]
`;
    const fixedNow = 1_000_000_000;
    const broker = new ApprovalBroker(60_000, 1000, () => fixedNow);
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow, broker });
    const inflight = send(handler, "POST", "/u/github/repos/o/r/pulls");
    broker.approve(await waitForApproval(broker), "ops");
    expect((await inflight).status).toBe(200);
    // Second identical pr:create -> now forwarded-before, no prompt.
    expect((await send(handler, "POST", "/u/github/repos/o/r/pulls")).status).toBe(200);
    log.close();
  });

  test("FIRST-USE: on_first deny blocks the first occurrence (403)", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
first_use:
  on_first: deny
  only: [repo:read]
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("first_use_denied");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("FIRST-USE: out-of-`only` action is never gated", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, pr:create]
first_use:
  on_first: deny
  only: ["pr:*"]
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    log.close();
  });

  test("FIRST-USE: never overrides an explicit deny", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny: [pr:merge]
first_use:
  on_first: require_approval
  only: ["pr:*"]
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow });
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("FIRST-USE: a novel action smuggled inside an MCP batch is still gated", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: mcp
    allow: ["call:get_*", "call:delete_*"]
first_use:
  on_first: deny
  only: ["call:delete_*"]
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow });
    // A 2-message batch: one benign get + one novel delete. The collapsed action
    // is batch:2, but member gating must still catch the delete.
    const batch = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_x" } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_y" } },
    ]);
    const res = await send(handler, "POST", "/u/mcp", { body: batch });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("first_use_denied");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("FIRST-USE: a jit_grant allow is not first-use-clamped", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
first_use:
  on_first: deny
  only: ["pr:*"]
`;
    const fixedNow = 1_000_000_000;
    const grants = makeGrants();
    // pr:create is a policy gap widened by the grant -> jit_grant allow; the
    // grant is the human decision, so first-use must NOT re-clamp it.
    grants.mint({ agentId: "claude-code", actions: ["pr:create"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow, grants });
    expect((await send(handler, "POST", "/u/github/repos/o/r/pulls")).status).toBe(200);
    log.close();
  });

  // Regression: first-use used to be guarded on `decision === "allow"`, so ANY
  // earlier clamp to require_approval (a closed schedule, a static
  // require_approval rule) swallowed an `on_first: deny` — turning a hard "never
  // on first use" into a prompt a tired human nods through at 3am.
  test("FIRST-USE: on_first deny survives a closed schedule's approval clamp", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  timezone: UTC
  on_closed: require_approval
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "17:00"
first_use:
  on_first: deny
  only: [repo:read]
`;
    const sundayNoon = Date.UTC(2024, 6, 14, 12, 0); // closed window
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => sundayNoon });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("first_use_denied");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("FIRST-USE: on_first deny survives a static require_approval rule", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    require_approval: [repo:read]
first_use:
  on_first: deny
  only: [repo:read]
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => fixedNow });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("first_use_denied");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("FIRST-USE: on_first require_approval under a closed schedule still prompts once", async () => {
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  timezone: UTC
  on_closed: require_approval
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "17:00"
first_use:
  on_first: require_approval
  only: [repo:read]
`;
    const sundayNoon = Date.UTC(2024, 6, 14, 12, 0);
    const broker = new ApprovalBroker(60_000, 1000, () => sundayNoon);
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => sundayNoon, broker });
    const inflight = send(handler, "GET", "/u/github/repos/o/r");
    broker.approve(await waitForApproval(broker), "ops");
    expect((await inflight).status).toBe(200);
    log.close();
  });

  test("FIRST-USE: a jit_grant survives a closed-schedule clamp without re-clamping", async () => {
    // The jit_grant skip keys off the `viaGrant` flag, not `result.reason` — a
    // schedule clamp overwrites the reason, and the skip must survive that.
    const fuPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
schedule:
  timezone: UTC
  on_closed: require_approval
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "17:00"
first_use:
  on_first: deny
  only: ["pr:*"]
`;
    const sundayNoon = Date.UTC(2024, 6, 14, 12, 0);
    const grants = makeGrants();
    grants.mint({ agentId: "claude-code", actions: ["pr:create"], ttlMs: 60_000, reason: "hotfix", now: sundayNoon });
    const broker = new ApprovalBroker(60_000, 1000, () => sundayNoon);
    const { handler, log } = await makeEnv({ policy: fuPolicy, now: () => sundayNoon, grants, broker });
    const inflight = send(handler, "POST", "/u/github/repos/o/r/pulls");
    // The closed schedule still asks (that clamp is not skipped for a grant),
    // but first-use must not turn it into a hard 403.
    broker.approve(await waitForApproval(broker), "ops");
    expect((await inflight).status).toBe(200);
    log.close();
  });

  test("TARGET SCOPE: allow constrained to a path prefix", async () => {
    const scopedPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow:
      - repo:read
      - action: "pr:*"
        targets: ["/repos/acme/*"]
`;
    const { handler, log } = await makeEnv({ policy: scopedPolicy });
    // In-scope target -> forwarded
    const ok = await send(handler, "POST", "/u/github/repos/acme/web/pulls", { body: "{}" });
    expect(ok.status).toBe(200);
    // Same ACTION, different target -> default deny
    const miss = await send(handler, "POST", "/u/github/repos/other/web/pulls", { body: "{}" });
    expect(miss.status).toBe(403);
    expect(miss.headers.get("x-grenz-reason")).toBe("no_matching_allow");
    // Unscoped rule still matches anywhere
    expect((await send(handler, "GET", "/u/github/repos/anyone/anything")).status).toBe(200);
    log.close();
  });

  test("TARGET SCOPE: scoped deny fires only on its targets", async () => {
    const scopedDeny = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: ["pr:*"]
    deny:
      - action: "pr:*"
        targets: ["/repos/prod-*"]
`;
    const { handler, log } = await makeEnv({ policy: scopedDeny });
    const denied = await send(handler, "POST", "/u/github/repos/prod-api/core/pulls", { body: "{}" });
    expect(denied.status).toBe(403);
    expect(denied.headers.get("x-grenz-reason")).toBe("explicit_deny");
    expect((await send(handler, "POST", "/u/github/repos/sandbox/core/pulls", { body: "{}" })).status).toBe(200);
    log.close();
  });

  test("TARGET SCOPE: a scoped deny is case-insensitive (mis-case can't dodge it)", async () => {
    const policy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: ["pr:*"]
    deny:
      - action: "pr:*"
        targets: ["/repos/prod-*"]
`;
    const { handler, log } = await makeEnv({ policy });
    // exact case -> denied
    const exact = await send(handler, "POST", "/u/github/repos/prod-api/x/pulls", { body: "{}" });
    expect(exact.headers.get("x-grenz-reason")).toBe("explicit_deny");
    // MIS-CASED -> still denied (previously this dodged the deny and fell through
    // to the broad `allow: [pr:*]` -> a forwarded merge without the guard)
    const dodged = await send(handler, "POST", "/u/github/repos/PROD-api/x/pulls", { body: "{}" });
    expect(dodged.status).toBe(403);
    expect(dodged.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("TARGET SCOPE: a scoped allow stays case-sensitive (no over-allow)", async () => {
    const policy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow:
      - action: "pr:*"
        targets: ["/repos/acme/*"]
`;
    const { handler, log } = await makeEnv({ policy });
    // exact case allowed
    expect((await send(handler, "POST", "/u/github/repos/acme/web/pulls", { body: "{}" })).status).toBe(200);
    // mis-cased NOT over-allowed -> default deny
    const miss = await send(handler, "POST", "/u/github/repos/ACME/web/pulls", { body: "{}" });
    expect(miss.status).toBe(403);
    expect(miss.headers.get("x-grenz-reason")).toBe("no_matching_allow");
    log.close();
  });

  test("PER-UPSTREAM BUDGET: caps one upstream, others still flow", async () => {
    const perPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
  - tool: mcp
    allow: ["session:*", "tools:list"]
budget:
  max_actions_per_hour: 1000
  per_upstream:
    github: 2
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: perPolicy, now: () => fixedNow });
    // github is capped at 2/hour
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    const third = await send(handler, "GET", "/u/github/repos/o/r");
    expect(third.status).toBe(429);
    expect(third.headers.get("x-grenz-reason")).toBe("upstream_budget_exceeded");
    // mcp has no per-upstream cap and the global ceiling has headroom -> still flows
    const mcpBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect((await send(handler, "POST", "/u/mcp/rpc", { body: mcpBody })).status).toBe(200);
    log.close();
  });

  test("PER-UPSTREAM BUDGET: global ceiling still reports budget_exceeded", async () => {
    const perPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 1
  per_upstream:
    github: 100
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: perPolicy, now: () => fixedNow });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    const second = await send(handler, "GET", "/u/github/repos/o/r");
    expect(second.status).toBe(429);
    expect(second.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    log.close();
  });

  test("PER-AGENT BUDGET: an override caps one agent; others use the default", async () => {
    const perAgentPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 100
  per_agent:
    ci-bot: 1
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: perAgentPolicy, now: () => fixedNow });
    // ci-bot is overridden to 1/hour
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: CI_TOKEN })).status).toBe(200);
    const second = await send(handler, "GET", "/u/github/repos/o/r", { token: CI_TOKEN });
    expect(second.status).toBe(429);
    expect(second.headers.get("x-grenz-reason")).toBe("agent_budget_exceeded");
    // claude-code has no per_agent entry -> the 100 default still has headroom
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    log.close();
  });

  test("PER-AGENT BUDGET: an unlisted agent hitting the global default reports budget_exceeded", async () => {
    const perAgentPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 1
  per_agent:
    ci-bot: 50
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: perAgentPolicy, now: () => fixedNow });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    const second = await send(handler, "GET", "/u/github/repos/o/r");
    expect(second.status).toBe(429);
    expect(second.headers.get("x-grenz-reason")).toBe("budget_exceeded"); // not agent_*
    log.close();
  });

  test("PER-AGENT BUDGET: an override ABOVE the global default raises that agent's ceiling", async () => {
    const perAgentPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 1
  per_agent:
    ci-bot: 3
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: perAgentPolicy, now: () => fixedNow });
    // ci-bot may exceed the global 1 because its override is 3
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: CI_TOKEN })).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: CI_TOKEN })).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: CI_TOKEN })).status).toBe(200);
    const fourth = await send(handler, "GET", "/u/github/repos/o/r", { token: CI_TOKEN });
    expect(fourth.status).toBe(429);
    expect(fourth.headers.get("x-grenz-reason")).toBe("agent_budget_exceeded");
    log.close();
  });

  test("MCP passthrough: allowed tool call forwards body + injects mcp credential", async () => {
    const { handler, log } = await makeEnv();
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_thing" } });
    const res = await send(handler, "POST", "/u/mcp", { body });
    expect(res.status).toBe(200);
    expect(cap.count).toBe(1);
    expect(cap.auth).toBe(`Bearer ${MCP_CRED}`);
    expect(cap.body).toBe(body); // request body forwarded intact
    log.close();
  });

  test("BUDGET: an MCP batch is billed per sub-action, not per request", async () => {
    const budgetPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: mcp
    allow: ["call:get_*"]
budget:
  max_actions_per_hour: 3
`;
    const fixedNow = 2_000_000_000;
    const { handler, log } = await makeEnv({ policy: budgetPolicy, now: () => fixedNow });
    const batchOf = (n: number): string =>
      JSON.stringify(
        Array.from({ length: n }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "get_x" } })),
      );

    // A batch of 2 allowed calls consumes 2 of the 3-action budget.
    expect((await send(handler, "POST", "/u/mcp", { body: batchOf(2) })).status).toBe(200);
    // A second batch of 2 would need 2 more (total 4) -> over budget, denied whole.
    const over = await send(handler, "POST", "/u/mcp", { body: batchOf(2) });
    expect(over.status).toBe(429);
    expect(over.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    // The single forwarded batch is the only upstream call; budget spent = 2.
    expect(cap.count).toBe(1);
    expect(log.countAllowedSince("claude-code", 0)).toBe(2);
    log.close();
  });

  test("WEIGHTED BUDGET: an action consumes its weight", async () => {
    const wPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, pr:create]
budget:
  max_actions_per_hour: 10
  weights:
    "pr:create": 10
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: wPolicy, now: () => fixedNow });
    // One pr:create costs 10 -> exactly the ceiling; a second is over budget.
    expect((await send(handler, "POST", "/u/github/repos/o/r/pulls")).status).toBe(200);
    const over = await send(handler, "POST", "/u/github/repos/o/r/pulls");
    expect(over.status).toBe(429);
    expect(over.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    // A cheap read (cost 1) is already over budget too (10 spent >= 10).
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(429);
    log.close();
  });

  test("WEIGHTED BUDGET: an MCP batch sums member weights", async () => {
    const wPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: mcp
    allow: ["call:get_*"]
budget:
  max_actions_per_hour: 5
  weights:
    "call:*": 3
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: wPolicy, now: () => fixedNow });
    const batchOf = (n: number): string =>
      JSON.stringify(
        Array.from({ length: n }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "get_x" } })),
      );
    // A batch of 2 calls at weight 3 each = 6 > ceiling 5 -> denied whole.
    const res = await send(handler, "POST", "/u/mcp", { body: batchOf(2) });
    expect(res.status).toBe(429);
    expect(res.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("WEIGHTED BUDGET: a doomed weighted approval is denied before the broker", async () => {
    const wPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    require_approval: [issue:update]
budget:
  max_actions_per_hour: 5
  weights:
    "issue:update": 10
`;
    const fixedNow = 1_000_000_000;
    const broker = new ApprovalBroker(60_000, 1000, () => fixedNow);
    const { handler, log } = await makeEnv({ policy: wPolicy, now: () => fixedNow, broker });
    // issue:update costs 10 > ceiling 5, so the approval is pre-gated on budget
    // and denied BEFORE a human/socket is held — no pending approval is created.
    const res = await send(handler, "PATCH", "/u/github/repos/o/r/issues/1", { body: "{}" });
    expect(res.status).toBe(429);
    expect(res.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    expect(broker.list().length).toBe(0);
    log.close();
  });

  test("WEIGHTED BUDGET: a shadow-suppressed weighted row bills 0", async () => {
    const wPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 10
  weights:
    "pr:create": 10
`;
    const fixedNow = 1_000_000_000;
    // pr:create is NOT allowed -> a policy deny that --shadow forwards for
    // observation. A suppressed row bills 0 regardless of its weight, so the
    // budget never accumulates: repeated calls all forward and spend stays 0.
    const { handler, log } = await makeEnv({ policy: wPolicy, now: () => fixedNow, shadow: true });
    expect((await send(handler, "POST", "/u/github/repos/o/r/pulls")).status).toBe(200);
    expect((await send(handler, "POST", "/u/github/repos/o/r/pulls")).status).toBe(200);
    expect(log.countAllowedSince("claude-code", 0)).toBe(0);
    log.close();
  });

  test("MCP passthrough: disallowed tool call denied", async () => {
    const { handler, log } = await makeEnv();
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "delete_thing" } });
    const res = await send(handler, "POST", "/u/mcp", { body });
    expect(res.status).toBe(403);
    expect(cap.count).toBe(0);
    log.close();
  });

  test("linear adapter (Gate 3): tool names map to canonical actions end-to-end", async () => {
    const { handler, log } = await makeEnv();
    const call = (name: string): string =>
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name } });

    // list_issues -> issue:read (allowed) → forwarded with the linear credential.
    const read = await send(handler, "POST", "/u/linear", { body: call("list_issues") });
    expect(read.status).toBe(200);
    expect(cap.auth).toBe(`Bearer ${MCP_CRED}`);

    // delete_comment -> comment:delete (a REAL Linear tool, denied by policy).
    const del = await send(handler, "POST", "/u/linear", { body: call("delete_comment") });
    expect(del.status).toBe(403);
    expect(del.headers.get("x-grenz-reason")).toBe("explicit_deny");

    // save_issue -> issue:write (not allowed) → default deny.
    const create = await send(handler, "POST", "/u/linear", { body: call("save_issue") });
    expect(create.status).toBe(403);
    expect(create.headers.get("x-grenz-reason")).toBe("no_matching_allow");
    log.close();
  });

  test("NO CREDENTIAL IN LOGS: neither the vault credential nor the token is on disk or in log lines", async () => {
    const { handler, log, emitted } = await makeEnv();
    await send(handler, "GET", "/u/github/repos/o/r"); // allow
    await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge"); // deny
    log.close(); // flush WAL

    // Every file the log wrote (db, -wal, -shm) is free of secrets.
    const files = await readdir(tmp);
    for (const f of files) {
      const bytes = new Uint8Array(await Bun.file(join(tmp, f)).arrayBuffer());
      assertNoSecretIn(new TextDecoder().decode(bytes));
    }
    // And the operational stderr lines are free of secrets.
    assertNoSecretIn(emitted.join("\n"));
    expect(emitted.length).toBe(2);
  });

  test("DLP: a secret in the body blocks the request and never leaks", async () => {
    const dlpPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
dlp:
  scan_bodies: true
  on_match: deny
`;
    const { handler, log, emitted } = await makeEnv({ policy: dlpPolicy });
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const body = JSON.stringify({ title: "add feature", body: `deploy key: ${secret}` });
    const res = await send(handler, "POST", "/u/github/repos/o/r/pulls", { body });

    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("dlp_secret_detected");
    expect(cap.count).toBe(0); // never forwarded upstream

    // The secret must not appear in the response, the operational lines, or on disk.
    expect(await res.text()).not.toContain(secret);
    expect(emitted.join("\n")).not.toContain(secret);
    expect(emitted.join("\n")).toContain("aws_access_key"); // detector name is fine
    log.close();
    for (const f of await readdir(tmp)) {
      const bytes = new Uint8Array(await Bun.file(join(tmp, f)).arrayBuffer());
      expect(new TextDecoder().decode(bytes)).not.toContain(secret);
    }
  });

  test("DLP: a clean body forwards normally", async () => {
    const dlpPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
dlp:
  scan_bodies: true
  on_match: deny
`;
    const { handler, log } = await makeEnv({ policy: dlpPolicy });
    const res = await send(handler, "POST", "/u/github/repos/o/r/pulls", {
      body: JSON.stringify({ title: "add feature", body: "a normal description" }),
    });
    expect(res.status).toBe(200);
    expect(cap.count).toBe(1);
    log.close();
  });

  test("health + info routes need no auth, expose no secrets and no PII/topology", async () => {
    const { handler, log } = await makeEnv();
    const health = await handler(new Request("http://grenz.local/healthz"));
    expect(health.status).toBe(200);
    const info = await handler(new Request("http://grenz.local/"));
    expect(info.status).toBe(200);
    const text = await info.text();
    assertNoSecretIn(text);
    // No agent id, on_behalf_of email, or upstream names leaked to an
    // unauthenticated caller.
    expect(text).not.toContain("am@team.dev");
    expect(text).not.toContain("claude-code");
    expect(text).not.toContain("github");
    log.close();
  });
});

const APPROVAL_PATH = "/u/github/repos/o/r/issues/5"; // PATCH -> issue:update -> require_approval

describe("approvals (Gate 2)", () => {
  test("approved request falls through to forward and logs approval_granted", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    expect(broker.approve(id, "test")).toBe(true);

    const res = await pending;
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    expect(cap.count).toBe(1); // forwarded only after approval
    const row = log.recent(1)[0]!;
    expect(row.decision).toBe("allow");
    expect(row.reason).toBe("approval_granted");
    log.close();
  });

  test("a require_approval rule's message reaches the approver as context", async () => {
    const policy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    require_approval:
      - action: issue:update
        message: "confirm the change is on a tracked ticket"
`;
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ policy, broker });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    expect(broker.get(id)!.context).toBe("confirm the change is on a tracked ticket");
    broker.approve(id, "ops");
    await pending;
    log.close();
  });

  test("a require_approval with no message has undefined approver context (regression)", async () => {
    const broker = new ApprovalBroker(10_000); // default POLICY: require_approval: [issue:update], no message
    const { handler, log } = await makeEnv({ broker });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    expect(broker.get(id)!.context).toBeUndefined();
    broker.approve(id, "ops");
    await pending;
    log.close();
  });

  test("resolution fires approvalResolved with the outcome (approved)", async () => {
    const resolved: { state: string; decidedBy: string | null }[] = [];
    const notifier: Notifier = {
      async approvalRequested() {},
      async approvalResolved(_r, o) {
        resolved.push({ state: o.state, decidedBy: o.decidedBy });
      },
    };
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker, notifier });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    broker.approve(id, "ops");
    await pending;
    await new Promise((r) => setTimeout(r, 10)); // fire-and-forget settles on a microtask
    expect(resolved).toEqual([{ state: "approved", decidedBy: "ops" }]);
    log.close();
  });

  test("resolution fires approvalResolved on client-disconnect (abandoned)", async () => {
    const resolved: string[] = [];
    const notifier: Notifier = {
      async approvalRequested() {},
      async approvalResolved(_r, o) {
        resolved.push(o.state);
      },
    };
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker, notifier });
    const ac = new AbortController();
    const pending = handler(
      new Request(`http://grenz.local${APPROVAL_PATH}`, {
        method: "PATCH",
        headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
        body: "{}",
        signal: ac.signal,
      }),
    );
    await waitForApproval(broker);
    ac.abort();
    await pending;
    await new Promise((r) => setTimeout(r, 10));
    expect(resolved).toEqual(["abandoned"]);
    log.close();
  });

  const QUORUM_POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    require_approval: [issue:update]
quorum:
  "issue:update": 2
`;

  test("quorum 2: needs two DISTINCT approvers before the action forwards", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ policy: QUORUM_POLICY, broker });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    expect(broker.approveBy(id, "alice").status).toBe("recorded");
    await new Promise((r) => setTimeout(r, 10));
    expect(cap.count).toBe(0); // one approver is not enough — still blocked
    expect(broker.approveBy(id, "bob").status).toBe("settled");
    const res = await pending;
    expect(res.status).toBe(200);
    expect(cap.count).toBe(1); // forwarded only after the SECOND distinct approver
    log.close();
  });

  test("quorum 2: one veto after a partial approve denies (deny-by-default)", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ policy: QUORUM_POLICY, broker });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    broker.approveBy(id, "alice");
    broker.deny(id, "carol");
    const res = await pending;
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approval_denied");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("quorum 2 never reuses a remembered approval — always fresh", async () => {
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const { handler, log } = await makeEnv({ policy: QUORUM_POLICY, broker, approvalMemory: memory });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id1 = await waitForApproval(broker);
    broker.approveBy(id1, "alice");
    broker.approveBy(id1, "bob");
    expect((await first).status).toBe(200);
    // An identical second request must prompt AGAIN and STILL need two approvers.
    const second = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id2 = await waitForApproval(broker);
    expect(id2).not.toBe(id1);
    broker.approveBy(id2, "alice");
    broker.approveBy(id2, "bob");
    expect((await second).status).toBe(200);
    log.close();
  });

  test("quorum 2 still honors a remembered DENY (sticky-deny stays)", async () => {
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const { handler, log } = await makeEnv({ policy: QUORUM_POLICY, broker, approvalMemory: memory });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.deny(await waitForApproval(broker), "carol"); // a single veto settles denied
    expect((await first).status).toBe(403);
    // The remembered deny short-circuits an identical retry — no new prompt.
    const second = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(second.status).toBe(403);
    expect(second.headers.get("x-grenz-reason")).toBe("approval_remembered_deny");
    expect(broker.pendingCount()).toBe(0);
    log.close();
  });

  test("console approve: two DISTINCT approver tokens settle a quorum-2", async () => {
    const ADMIN = "admin-token-xyz";
    const broker = new ApprovalBroker(10_000);
    const tokenStore = new TokenStore(join(tmp, "admin-tokens.json"));
    const aliceTok = (await tokenStore.create("alice", "approver", 1000)).token;
    const bobTok = (await tokenStore.create("bob", "approver", 1000)).token;
    const { handler, log } = await makeEnv({ policy: QUORUM_POLICY, broker, adminToken: ADMIN, tokenStore });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    const post = (token: string) =>
      handler(
        new Request(`http://grenz.local/console/approvals/${id}/approve`, {
          method: "POST",
          headers: { "x-grenz-admin": token, "content-type": "application/json" },
          body: "{}",
        }),
      );
    const b1 = (await (await post(aliceTok)).json()) as { by: string; satisfied: boolean; approvals: number; quorum: number };
    expect(b1.by).toBe("alice");
    expect(b1.satisfied).toBe(false);
    expect(b1.approvals).toBe(1);
    expect(b1.quorum).toBe(2);
    expect(cap.count).toBe(0);
    const b2 = (await (await post(bobTok)).json()) as { satisfied: boolean };
    expect(b2.satisfied).toBe(true);
    expect((await pending).status).toBe(200);
    expect(cap.count).toBe(1);
    log.close();
  });

  test("console approve: the SAME token twice does not settle a quorum-2", async () => {
    const ADMIN = "admin-token-xyz";
    const broker = new ApprovalBroker(10_000);
    const tokenStore = new TokenStore(join(tmp, "admin-tokens.json"));
    const aliceTok = (await tokenStore.create("alice", "approver", 1000)).token;
    const { handler, log } = await makeEnv({ policy: QUORUM_POLICY, broker, adminToken: ADMIN, tokenStore });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    const post = (token: string) =>
      handler(
        new Request(`http://grenz.local/console/approvals/${id}/approve`, {
          method: "POST",
          headers: { "x-grenz-admin": token, "content-type": "application/json" },
          body: "{}",
        }),
      );
    await post(aliceTok);
    const dup = (await (await post(aliceTok)).json()) as { satisfied: boolean; approvals: number };
    expect(dup.satisfied).toBe(false);
    expect(dup.approvals).toBe(1);
    expect(cap.count).toBe(0);
    broker.deny(id, "cleanup");
    await pending;
    log.close();
  });

  test("client disconnect mid-approval -> cancelled, never forwarded (approval_abandoned)", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker });
    const ac = new AbortController();
    const pending = handler(
      new Request(`http://grenz.local${APPROVAL_PATH}`, {
        method: "PATCH",
        headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
        body: "{}",
        signal: ac.signal,
      }),
    );
    const id = await waitForApproval(broker);
    expect(broker.list().length).toBe(1);
    ac.abort(); // the agent gives up while a human is still deciding
    await new Promise((r) => setTimeout(r, 20));
    expect(broker.list().length).toBe(0); // cancelled — fails fast without the fix
    const res = await pending;
    expect(res.headers.get("x-grenz-reason")).toBe("approval_abandoned");
    expect(res.status).toBe(499);
    expect(cap.count).toBe(0); // credential never fetched, action never forwarded
    const row = log.recent(1)[0]!;
    expect(row.decision).toBe("deny");
    expect(row.reason).toBe("approval_abandoned");
    expect(row.forwarded).toBe(false);
    log.close();
  });

  test("request already aborted before approval is created -> abandoned, not forwarded", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker });
    const ac = new AbortController();
    ac.abort(); // gone before we even start
    const res = await handler(
      new Request(`http://grenz.local${APPROVAL_PATH}`, {
        method: "PATCH",
        headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
        body: "{}",
        signal: ac.signal,
      }),
    );
    expect(res.headers.get("x-grenz-reason")).toBe("approval_abandoned");
    expect(broker.list().length).toBe(0);
    expect(cap.count).toBe(0);
    log.close();
  });

  test("denied request -> 403 approval_denied, never forwarded", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    broker.deny(id, "test");

    const res = await pending;
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approval_denied");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("no decision within TTL -> 403 approval_expired (expire → DENY)", async () => {
    const broker = new ApprovalBroker(40);
    const { handler, log } = await makeEnv({ broker });
    const res = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approval_expired");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("with no broker, require_approval still blocks as approvals_unavailable", async () => {
    const { handler, log } = await makeEnv(); // no broker
    const res = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("pending-approval cap -> 429 approval_capacity (resource guard)", async () => {
    const broker = new ApprovalBroker(10_000, 1); // capacity of 1
    const { handler, log } = await makeEnv({ broker });
    const held = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" }); // fills capacity
    await waitForApproval(broker);
    const second = await send(handler, "PATCH", "/u/github/repos/o/r/issues/9", { body: "{}" });
    expect(second.status).toBe(429);
    expect(second.headers.get("x-grenz-reason")).toBe("approval_capacity");
    broker.drain();
    await held; // release the held one
    log.close();
  });

  test("a throwing notifier neither fails nor orphans the approval", async () => {
    const broker = new ApprovalBroker(10_000);
    const badNotifier: Notifier = {
      async approvalRequested() {
        throw new Error("boom");
      },
    };
    const { handler, log } = await makeEnv({ broker, notifier: badNotifier });
    const held = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);
    expect(broker.approve(id, "test")).toBe(true); // still decidable
    const res = await held;
    expect(res.status).toBe(200);
    log.close();
  });

  test("APPROVAL MEMORY: a remembered grant skips the second prompt", async () => {
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const { handler, log } = await makeEnv({ broker, approvalMemory: memory });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.approve(await waitForApproval(broker), "test");
    expect((await first).status).toBe(200);

    // identical request: resolves WITHOUT a new pending approval
    const second = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(second.status).toBe(200);
    expect(broker.pendingCount()).toBe(0);
    expect(cap.count).toBe(2); // both forwarded
    const row = log.recent(1)[0]!;
    expect(row.decision).toBe("allow");
    expect(row.reason).toBe("approval_remembered_grant");
    log.close();
  });

  test("APPROVAL MEMORY: a remembered deny blocks instantly without a prompt", async () => {
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const { handler, log } = await makeEnv({ broker, approvalMemory: memory });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.deny(await waitForApproval(broker), "test");
    expect((await first).status).toBe(403);

    const second = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(second.status).toBe(403);
    expect(second.headers.get("x-grenz-reason")).toBe("approval_remembered_deny");
    expect(broker.pendingCount()).toBe(0);
    expect(cap.count).toBe(0); // nothing ever forwarded
    log.close();
  });

  test("APPROVAL MEMORY: a different target still prompts", async () => {
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const { handler, log } = await makeEnv({ broker, approvalMemory: memory });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.approve(await waitForApproval(broker), "test");
    await first;

    const other = send(handler, "PATCH", "/u/github/repos/o/r/issues/6", { body: "{}" });
    const id2 = await waitForApproval(broker); // a FRESH prompt appeared
    broker.approve(id2, "test");
    expect((await other).status).toBe(200);
    log.close();
  });

  test("APPROVAL MEMORY: the window expires", async () => {
    let t = 1_000_000_000;
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(1_000, () => t);
    const { handler, log } = await makeEnv({ broker, approvalMemory: memory, now: () => t });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.approve(await waitForApproval(broker), "test");
    await first;

    t += 5_000; // past the 1s remember window
    const second = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id2 = await waitForApproval(broker); // prompts again
    broker.approve(id2, "test");
    expect((await second).status).toBe(200);
    log.close();
  });

  test("APPROVAL MEMORY: off by default — a repeat prompts again", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker }); // no memory dep
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.approve(await waitForApproval(broker), "test");
    await first;
    const second = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.approve(await waitForApproval(broker), "test"); // fresh prompt needed
    expect((await second).status).toBe(200);
    log.close();
  });

  test("APPROVAL MEMORY: a policy flip to deny beats a remembered grant", async () => {
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const compiled = compilePolicyYaml(POLICY);
    if (!compiled.ok) throw new Error(compiled.error);
    const store = new PolicyStore(compiled.policy);
    const { handler, log } = await makeEnv({ broker, approvalMemory: memory, policyStore: store });
    const first = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    broker.approve(await waitForApproval(broker), "test");
    expect((await first).status).toBe(200);

    // Tighten the live policy: issue:update becomes an explicit deny.
    const outcome = store.reload(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, pr:create, issue:read]
    deny: [pr:merge, issue:update]
`);
    expect(outcome.ok).toBe(true);
    const second = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(second.status).toBe(403);
    expect(second.headers.get("x-grenz-reason")).toBe("explicit_deny"); // memory never consulted
    log.close();
  });

  test("APPROVAL MEMORY: DLP-flagged prompts never reuse a decision", async () => {
    const dlpPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
dlp:
  scan_bodies: true
  on_match: require_approval
`;
    const broker = new ApprovalBroker(10_000);
    const memory = new ApprovalMemory(60_000);
    const { handler, log } = await makeEnv({ policy: dlpPolicy, broker, approvalMemory: memory });
    const body = JSON.stringify({ title: "x", body: "deploy key: AKIAIOSFODNN7EXAMPLE" });
    const first = send(handler, "POST", "/u/github/repos/o/r/pulls", { body });
    broker.approve(await waitForApproval(broker), "test");
    expect((await first).status).toBe(200);

    // Identical secret-bearing request: must prompt a human AGAIN.
    const second = send(handler, "POST", "/u/github/repos/o/r/pulls", { body });
    const id2 = await waitForApproval(broker);
    broker.approve(id2, "test");
    expect((await second).status).toBe(200);
    log.close();
  });

  test("DLP-gate approval also honors client disconnect (abandoned, not forwarded)", async () => {
    const dlpPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
dlp:
  scan_bodies: true
  on_match: require_approval
`;
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ policy: dlpPolicy, broker });
    const body = JSON.stringify({ title: "x", body: "deploy key: AKIAIOSFODNN7EXAMPLE" });
    const ac = new AbortController();
    const pending = handler(
      new Request(`http://grenz.local/u/github/repos/o/r/pulls`, {
        method: "POST",
        headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
        body,
        signal: ac.signal,
      }),
    );
    await waitForApproval(broker);
    ac.abort();
    await new Promise((r) => setTimeout(r, 20));
    expect(broker.list().length).toBe(0);
    const res = await pending;
    expect(res.headers.get("x-grenz-reason")).toBe("approval_abandoned");
    expect(cap.count).toBe(0); // the secret-bearing body was never forwarded
    log.close();
  });

  test("over-budget require_approval is denied before asking a human", async () => {
    const policy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    require_approval: [issue:update]
budget:
  max_actions_per_hour: 1
`;
    const broker = new ApprovalBroker(10_000);
    const fixedNow = 3_000_000_000;
    const { handler, log } = await makeEnv({ policy, broker, now: () => fixedNow });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200); // spends the 1 unit
    const res = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(res.status).toBe(429);
    expect(res.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    expect(broker.pendingCount()).toBe(0); // never queued a doomed approval
    log.close();
  });
});

describe("console/admin API (Gate 2)", () => {
  const ADMIN = "admin-token-xyz";
  const adminReq = (path: string, method = "GET"): Request =>
    new Request(`http://grenz.local${path}`, { method, headers: { "x-grenz-admin": ADMIN } });

  test("requires the admin token", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    expect((await handler(new Request("http://grenz.local/console/summary"))).status).toBe(401);
    const wrong = await handler(
      new Request("http://grenz.local/console/summary", { headers: { "x-grenz-admin": "nope" } }),
    );
    expect(wrong.status).toBe(401);
    expect((await handler(adminReq("/console/summary"))).status).toBe(200);
    log.close();
  });

  test("GET /console/explain returns the live per-action verdict, admin-gated", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const explain = async (q: string) => {
      const res = await handler(adminReq(`/console/explain?${q}`));
      return { status: res.status, body: (await res.json()) as { effective?: { decision: string } } };
    };
    expect((await explain("tool=github&action=pr:merge")).body.effective?.decision).toBe("deny");
    expect((await explain("tool=github&action=issue:update")).body.effective?.decision).toBe(
      "require_approval",
    );
    expect((await explain("tool=github&action=repo:read")).body.effective?.decision).toBe("allow");
    // tool + action are required.
    expect((await explain("action=repo:read")).status).toBe(400);
    // Inherits the console admin gate.
    const noauth = await handler(
      new Request("http://grenz.local/console/explain?tool=github&action=repo:read"),
    );
    expect(noauth.status).toBe(401);
    // Decision metadata only — no credential material.
    const res = await handler(adminReq("/console/explain?tool=github&action=repo:read"));
    assertNoSecretIn(await res.text());
    log.close();
  });

  test("summary reflects allow/deny counts and leaks no secrets", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    await send(handler, "GET", "/u/github/repos/o/r"); // allow
    await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge"); // deny
    const res = await handler(adminReq("/console/summary"));
    const text = await res.clone().text();
    assertNoSecretIn(text);
    const s = (await res.json()) as Record<string, number>;
    expect(s.allow).toBe(1);
    expect(s.deny).toBe(1);
    log.close();
  });

  test("console summary includes remembered counts", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const res = await handler(adminReq("/console/summary"));
    const body = (await res.json()) as { rememberedGrant: number; rememberedDeny: number };
    expect(body.rememberedGrant).toBe(0);
    expect(body.rememberedDeny).toBe(0);
    log.close();
  });

  test("console budgets: per-agent ceilings + capped upstream spend (admin-gated)", async () => {
    const budgetPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 100
  per_agent:
    ci-bot: 5
  per_upstream:
    github: 50
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({ policy: budgetPolicy, adminToken: ADMIN, now: () => fixedNow });
    expect((await handler(new Request("http://grenz.local/console/budgets"))).status).toBe(401);

    // spend 2 github actions as claude-code
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);

    const res = await handler(adminReq("/console/budgets"));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      window_hours: number;
      agents: Array<{
        agent: string;
        limit: number | null;
        override: boolean;
        spent: number;
        upstreams: Array<{ upstream: string; limit: number; spent: number }>;
      }>;
    };
    expect(body.window_hours).toBe(1);
    const cc = body.agents.find((a) => a.agent === "claude-code")!;
    expect(cc).toBeDefined();
    expect(cc.limit).toBe(100);
    expect(cc.override).toBe(false);
    expect(cc.spent).toBe(2);
    expect(cc.upstreams).toEqual([{ upstream: "github", limit: 50, spent: 2 }]);
    const ci = body.agents.find((a) => a.agent === "ci-bot")!;
    expect(ci.limit).toBe(5);
    expect(ci.override).toBe(true);
    expect(ci.spent).toBe(0);
    log.close();
  });

  test("console budgets: no budget config -> null limits, no upstream rows", async () => {
    const noBudget = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
`;
    const { handler, log } = await makeEnv({ policy: noBudget, adminToken: ADMIN });
    const res = await handler(adminReq("/console/budgets"));
    const body = (await res.json()) as { agents: Array<{ limit: number | null; upstreams: unknown[] }> };
    expect(body.agents.every((a) => a.limit === null && a.upstreams.length === 0)).toBe(true);
    log.close();
  });

  test("console risk: one entry per configured agent (admin-gated)", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    expect((await handler(new Request("http://grenz.local/console/risk"))).status).toBe(401);
    const res = await handler(adminReq("/console/risk"));
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      window_minutes: number;
      agents: Array<{ agent: string; level: string; score: number; total: number; deny: number }>;
    };
    expect(body.window_minutes).toBe(15);
    const ids = body.agents.map((a) => a.agent).sort();
    expect(ids).toEqual(["ci-bot", "claude-code"]);
    expect(["low", "elevated", "high"]).toContain(body.agents[0]!.level);
    log.close();
  });

  test("approve endpoint decides a blocked request end-to-end", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker, adminToken: ADMIN });
    const pending = send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    const id = await waitForApproval(broker);

    const listed = (await (await handler(adminReq("/console/approvals"))).json()) as {
      approvals: Array<{ id: string }>;
    };
    expect(listed.approvals.length).toBe(1);
    expect(listed.approvals[0]!.id).toBe(id);

    const decided = await handler(adminReq(`/console/approvals/${id}/approve`, "POST"));
    expect(decided.status).toBe(200);
    const res = await pending;
    expect(res.status).toBe(200);
    log.close();
  });

  test("deciding an unknown approval id -> 404", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ broker, adminToken: ADMIN });
    const res = await handler(adminReq("/console/approvals/apr_nope/approve", "POST"));
    expect(res.status).toBe(404);
    log.close();
  });
});

describe("blast-radius (console)", () => {
  const ADMIN = "admin-token-xyz";
  const adminReq = (path: string): Request =>
    new Request(`http://grenz.local${path}`, { headers: { "x-grenz-admin": ADMIN } });

  test("requires the admin token", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    expect((await handler(new Request("http://grenz.local/console/blast-radius"))).status).toBe(401);
    log.close();
  });

  test("reports exposure per upstream for the policy's agent, leaking no secrets", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const res = await handler(adminReq("/console/blast-radius"));
    expect(res.status).toBe(200);
    const text = await res.clone().text();
    assertNoSecretIn(text);

    const report = (await res.json()) as {
      agent: string;
      severity: string;
      upstreams: Array<{
        upstream: string;
        enumerable: boolean;
        autoAllow: string[];
        requiresApproval: string[];
        rawPatterns?: { allow: string[] };
      }>;
      delegations: unknown[];
    };
    expect(report.agent).toBe("claude-code");

    const gh = report.upstreams.find((u) => u.upstream === "github")!;
    expect(gh.enumerable).toBe(true);
    expect(gh.autoAllow).toEqual(expect.arrayContaining(["repo:read", "pr:create", "issue:read"]));
    expect(gh.requiresApproval).toEqual(["issue:update"]);

    const mcp = report.upstreams.find((u) => u.upstream === "mcp")!;
    expect(mcp.enumerable).toBe(false);
    expect(mcp.rawPatterns?.allow).toEqual(
      expect.arrayContaining(["session:*", "tools:list", "call:get_*"]),
    );

    const deadgh = report.upstreams.find((u) => u.upstream === "deadgh")!;
    expect(deadgh.autoAllow).toEqual(["repo:read"]);

    log.close();
  });
});

describe("kill-switch (revocation)", () => {
  const ADMIN = "admin-token-xyz";
  const adminReq = (path: string, method = "GET"): Request =>
    new Request(`http://grenz.local${path}`, { method, headers: { "x-grenz-admin": ADMIN } });

  test("a revoked agent is denied before upstream, policy, or credential", async () => {
    const revocations = makeRevocations();
    revocations.revoke("claude-code", "risk:high", 1);
    const { handler, log } = await makeEnv({ revocations });
    // A request that is normally ALLOWED must now be denied at the door.
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    expect(cap.count).toBe(0); // never forwarded upstream
    const text = await res.text();
    assertNoSecretIn(text);
    log.close();
  });

  test("admin API revokes live then restores — mid-flight, same handler, no restart", async () => {
    const revocations = makeRevocations();
    const { handler, log } = await makeEnv({ revocations, adminToken: ADMIN });

    // Allowed before revocation.
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);

    // Revoke via the admin API — mutates the store the handler is already using.
    const rv = await handler(adminReq("/console/revocations/claude-code?reason=test", "POST"));
    expect(rv.status).toBe(200);

    // Now denied, with no restart.
    const denied = await send(handler, "GET", "/u/github/repos/o/r");
    expect(denied.status).toBe(403);
    expect(denied.headers.get("x-grenz-reason")).toBe("token_revoked");

    // Listed.
    const listed = (await (await handler(adminReq("/console/revocations"))).json()) as {
      revocations: Array<{ agentId: string }>;
    };
    expect(listed.revocations.length).toBe(1);
    expect(listed.revocations[0]!.agentId).toBe("claude-code");

    // Restore re-enables it, again with no restart.
    const rs = await handler(adminReq("/console/revocations/claude-code", "DELETE"));
    expect(rs.status).toBe(200);
    expect(((await rs.json()) as { removed: boolean }).removed).toBe(true);
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    log.close();
  });

  test("revocation endpoints require the admin token", async () => {
    const { handler, log } = await makeEnv({ revocations: makeRevocations(), adminToken: ADMIN });
    const unauth = await handler(new Request("http://grenz.local/console/revocations"));
    expect(unauth.status).toBe(401);
    const post = await handler(
      new Request("http://grenz.local/console/revocations/claude-code", { method: "POST" }),
    );
    expect(post.status).toBe(401);
    log.close();
  });

  test("with no store wired, no agent is revoked (opt-in)", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    // The revoke endpoint reports the feature is unavailable rather than 500.
    const rv = await handler(adminReq("/console/revocations/claude-code", "POST"));
    expect(rv.status).toBe(409);
    log.close();
  });
});

describe("fleet revocation (union at the gate)", () => {
  const ADMIN = "admin-token-xyz";
  const adminReq = (path: string, method = "GET"): Request =>
    new Request(`http://grenz.local${path}`, { method, headers: { "x-grenz-admin": ADMIN } });

  test("a fleet-revoked agent is denied with NO local revocation", async () => {
    const { handler, log } = await makeEnv({ fleetRevocations: makeFleet(["claude-code"], 3) });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    expect(cap.count).toBe(0); // never forwarded upstream
    log.close();
  });

  test("a locally-revoked agent stays denied when the fleet set OMITS it (no un-revoke)", async () => {
    const revocations = makeRevocations();
    revocations.revoke("claude-code", "risk:high", 1);
    // Fleet set does NOT contain claude-code — the union must not subtract.
    const { handler, log } = await makeEnv({ revocations, fleetRevocations: makeFleet(["someone-else"], 5) });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    log.close();
  });

  test("a non-listed agent passes when the fleet set does not list it and it is not stale", async () => {
    const { handler, log } = await makeEnv({ fleetRevocations: makeFleet(["other"], 2) });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    log.close();
  });

  test("staleClosed denies ALL requests with revocation_stale", async () => {
    const revocationDistribution: RevocationDistributionState = {
      version: 4,
      count: 0,
      expiresAt: null,
      lastVerifiedPullAt: 1,
      staleClosed: true,
    };
    const { handler, log } = await makeEnv({ fleetRevocations: makeFleet([], 4), revocationDistribution });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("revocation_stale");
    log.close();
  });

  test("restore refuses honestly on a fleet-revoked id (local lift, still fleet-cut)", async () => {
    const revocations = makeRevocations();
    revocations.revoke("claude-code", "local", 1);
    const revocationDistribution: RevocationDistributionState = {
      version: 9,
      count: 1,
      expiresAt: null,
      lastVerifiedPullAt: 1,
      staleClosed: false,
    };
    const { handler, log } = await makeEnv({
      revocations,
      fleetRevocations: makeFleet(["claude-code"], 9),
      revocationDistribution,
      adminToken: ADMIN,
    });
    const rs = await handler(adminReq("/console/revocations/claude-code", "DELETE"));
    expect(rs.status).toBe(200);
    const body = (await rs.json()) as { removed: boolean; fleet_revoked?: boolean; fleet_version?: number };
    expect(body.removed).toBe(true); // the LOCAL revocation was lifted
    expect(body.fleet_revoked).toBe(true); // but the agent is still cut off fleet-wide
    expect(body.fleet_version).toBe(9);
    // Still denied at the gate (fleet set stands).
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(403);
    log.close();
  });
});

describe("delegation (attenuated sub-tokens)", () => {
  const ADMIN = "admin-token-xyz";
  const adminReq = (path: string, method = "GET"): Request =>
    new Request(`http://grenz.local${path}`, { method, headers: { "x-grenz-admin": ADMIN } });

  interface MintResp { token: string; delegation_id: string; actions: string[]; targets?: string[]; expires_at: number }

  async function selfMint(handler: Env["handler"], body: object, token = TOKEN): Promise<MintResp> {
    const res = await send(handler, "POST", "/delegate", { token, body: JSON.stringify(body) });
    expect(res.status).toBe(200);
    return (await res.json()) as MintResp;
  }

  test("self-mint: child works IN scope, is denied OUT of scope (< parent)", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // Parent may repo:read AND pr:create; it delegates ONLY repo:read.
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });

    // In scope → forwarded like a normal allow.
    const inScope = await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    expect(inScope.status).toBe(200);

    // Out of scope → denied, even though the PARENT's policy allows pr:create.
    const outScope = await send(handler, "POST", "/u/github/repos/o/r/pulls", {
      token: child,
      body: "{}",
    });
    expect(outScope.status).toBe(403);
    expect(outScope.headers.get("x-grenz-reason")).toBe("delegation_scope");
    expect(cap.count).toBe(1); // only the in-scope call reached upstream
    log.close();
  });

  test("scope is the INTERSECTION: policy still clamps even if attenuation is broad", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // Delegate pr:merge — but the parent's policy DENIES pr:merge, so the child
    // gets policy's explicit_deny, never a privilege the parent lacks.
    const { token: child } = await selfMint(handler, { actions: ["pr:*"] });
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: child });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("multi-hop: a delegated token CAN re-delegate, narrowing further", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // agent → child (repo:read + pr:create) → grandchild (repo:read only).
    const { token: child } = await selfMint(handler, { actions: ["repo:read", "pr:create"] });
    const { token: grand } = await selfMint(handler, { actions: ["repo:read"] }, child);

    // Grandchild may repo:read (every hop + policy allow).
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: grand })).status).toBe(200);
    // Grandchild may NOT pr:create — its own grant dropped it, though the child
    // and the root policy both allow it.
    const denied = await send(handler, "POST", "/u/github/repos/o/r/pulls", { token: grand, body: "{}" });
    expect(denied.status).toBe(403);
    expect(denied.headers.get("x-grenz-reason")).toBe("delegation_scope");
    log.close();
  });

  test("the fold is monotone: a widened deeper hop grants nothing", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // Child narrows to repo:read only. Grandchild tries to REGAIN pr:create —
    // which the root policy DOES allow — but the child hop no longer matches it,
    // so the intersection denies it. A buggy/malicious middle hop cannot widen.
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });
    const { token: grand } = await selfMint(handler, { actions: ["pr:create", "repo:read"] }, child);

    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: grand })).status).toBe(200);
    const widened = await send(handler, "POST", "/u/github/repos/o/r/pulls", { token: grand, body: "{}" });
    expect(widened.status).toBe(403);
    expect(widened.headers.get("x-grenz-reason")).toBe("delegation_scope");
    log.close();
  });

  test("target scope: read IN target passes, read OUT of target is denied", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // repo:read is policy-allowed on ANY target. Attenuate the child to repos
    // under o/ only. The action is identical for both requests — only the
    // target differs, so a denial can come ONLY from target scope.
    const { token: child, targets } = await selfMint(handler, {
      actions: ["repo:read"],
      targets: ["/repos/o/*"],
    });
    expect(targets).toEqual(["/repos/o/*"]); // mint echoes the attenuation

    const inScope = await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    expect(inScope.status).toBe(200);

    const outScope = await send(handler, "GET", "/u/github/repos/other/secret", { token: child });
    expect(outScope.status).toBe(403);
    expect(outScope.headers.get("x-grenz-reason")).toBe("delegation_target_scope");
    expect(cap.count).toBe(1); // only the in-target read reached upstream
    log.close();
  });

  test("target scope: no targets = unrestricted by target (back-compat)", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });
    // Any repo path is reachable — the grant places no target constraint.
    expect((await send(handler, "GET", "/u/github/repos/anything/at/all", { token: child })).status).toBe(200);
    log.close();
  });

  test("target scope is the INTERSECTION: a widened deeper hop grants no target", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // Child is pinned to o/*. Grandchild tries to widen to ALL repos — but the
    // child hop still gates, so o/ is the only reachable prefix.
    const { token: child } = await selfMint(handler, { actions: ["repo:read"], targets: ["/repos/o/*"] });
    const { token: grand } = await selfMint(handler, { actions: ["repo:read"], targets: ["/repos/*"] }, child);

    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: grand })).status).toBe(200);
    const widened = await send(handler, "GET", "/u/github/repos/x/y", { token: grand });
    expect(widened.status).toBe(403);
    expect(widened.headers.get("x-grenz-reason")).toBe("delegation_target_scope");
    log.close();
  });

  test("action scope is checked before target scope", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // Child may only repo:read under o/*. A pr:create (action out of scope) to an
    // out-of-target path denies on ACTION first — the more specific signal.
    const { token: child } = await selfMint(handler, { actions: ["repo:read"], targets: ["/repos/o/*"] });
    const res = await send(handler, "POST", "/u/github/repos/x/y/pulls", { token: child, body: "{}" });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("delegation_scope");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("chain depth is capped: minting past MAX_DEPTH is refused", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    // Build a chain of exactly MAX_DEPTH grants (agent mints d1; each mints next).
    let token = TOKEN;
    for (let i = 0; i < 5; i++) {
      token = (await selfMint(handler, { actions: ["repo:read"] }, token)).token;
    }
    // The next hop would be MAX_DEPTH+1 → refused, not minted.
    const res = await send(handler, "POST", "/delegate", {
      token,
      body: JSON.stringify({ actions: ["repo:read"] }),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("delegation_depth");
    log.close();
  });

  test("cascade: revoking a MIDDLE grant cuts off its descendants, not its ancestors", async () => {
    const revocations = makeRevocations();
    const { handler, log } = await makeEnv({ delegations: makeDelegations(), revocations });
    const { token: child, delegation_id: childId } = await selfMint(handler, { actions: ["repo:read"] });
    const { token: grand } = await selfMint(handler, { actions: ["repo:read"] }, child);

    // Both live at first.
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: grand })).status).toBe(200);

    // Revoke the MIDDLE grant: the grandchild dies (its chain contains childId),
    // but the root agent keeps working.
    revocations.revoke(childId, "compromised sub-agent", 1);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: grand })).status).toBe(403);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: TOKEN })).status).toBe(200);
    log.close();
  });

  test("cascade: revoking the PARENT cuts off every child it spawned", async () => {
    const revocations = makeRevocations();
    const { handler, log } = await makeEnv({ delegations: makeDelegations(), revocations });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);

    // Kill the parent agent — the child dies with it, no restart.
    revocations.revoke("claude-code", "compromised", 1);
    const res = await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    log.close();
  });

  test("a single delegation can be revoked on its own id; the parent keeps working", async () => {
    const revocations = makeRevocations();
    const { handler, log } = await makeEnv({ delegations: makeDelegations(), revocations });
    const { token: child, delegation_id } = await selfMint(handler, { actions: ["repo:read"] });

    revocations.revoke(delegation_id, "just this one", 1);
    // Child denied...
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(403);
    // ...but the parent (and any other delegation) is unaffected.
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    log.close();
  });

  test("an expired child token no longer authenticates", async () => {
    let clock = 1000;
    const { handler, log } = await makeEnv({ delegations: makeDelegations(), now: () => clock });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"], ttl_seconds: 60 });
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    clock = 1000 + 61_000; // past the 60s TTL
    const res = await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    expect(res.status).toBe(401);
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token");
    log.close();
  });

  test("admin mint on behalf of a configured agent; unknown agent → 404", async () => {
    const delegations = makeDelegations();
    const { handler, log } = await makeEnv({ delegations, adminToken: ADMIN });

    const ok = await handler(adminReq("/console/delegations?agent=claude-code&actions=repo:read", "POST"));
    expect(ok.status).toBe(200);
    const child = ((await ok.json()) as MintResp).token;
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);

    const listed = (await (await handler(adminReq("/console/delegations"))).json()) as {
      delegations: Array<{ parent: string; revoked: boolean }>;
    };
    expect(listed.delegations.length).toBe(1);
    expect(listed.delegations[0]!.parent).toBe("claude-code");

    const bad = await handler(adminReq("/console/delegations?agent=ghost&actions=repo:read", "POST"));
    expect(bad.status).toBe(404);
    log.close();
  });

  test("the minted child token never appears in logs on disk", async () => {
    const { handler, log } = await makeEnv({ delegations: makeDelegations() });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });
    await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    log.close();
    for (const f of await readdir(tmp)) {
      if (f === "delegations.json") continue; // stores the HASH, asserted elsewhere
      const bytes = new Uint8Array(await Bun.file(join(tmp, f)).arrayBuffer());
      expect(new TextDecoder().decode(bytes)).not.toContain(child);
    }
  });

  test("DELEGATION BUDGET: each child individually capped while the parent flows", async () => {
    const perDelegationPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 100
  per_delegation: 1
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({
      policy: perDelegationPolicy,
      delegations: makeDelegations(),
      now: () => fixedNow,
    });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });

    // The child spends its own ceiling of 1...
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    const second = await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    expect(second.status).toBe(429);
    expect(second.headers.get("x-grenz-reason")).toBe("delegation_budget_exceeded");

    // ...while the PARENT still flows: the cap is additive, not shared.
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);

    // ...and a fresh SIBLING has its own headroom: per-token, not per-family.
    const { token: sibling } = await selfMint(handler, { actions: ["repo:read"] });
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: sibling })).status).toBe(200);
    log.close();
  });

  test("DELEGATION BUDGET: child spend still counts against the parent ceiling (additive)", async () => {
    const perDelegationPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 2
  per_delegation: 2
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({
      policy: perDelegationPolicy,
      delegations: makeDelegations(),
      now: () => fixedNow,
    });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });

    // The child consumes the PARENT's whole ceiling (rows carry agent_id = parent)...
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);

    // ...so the parent itself is now out of budget — the shared-ceiling
    // invariant is unchanged by the new per-token cap.
    const parentNow = await send(handler, "GET", "/u/github/repos/o/r");
    expect(parentNow.status).toBe(429);
    expect(parentNow.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    log.close();
  });

  test("console: /console/delegations rows carry per-token spent", async () => {
    const { handler, log } = await makeEnv({
      delegations: makeDelegations(),
      adminToken: ADMIN,
    });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);

    const listed = (await (await handler(adminReq("/console/delegations"))).json()) as {
      delegations: Array<{ id: string; spent: number }>;
    };
    expect(listed.delegations.length).toBe(1);
    expect(listed.delegations[0]!.spent).toBe(1);
    log.close();
  });

  test("DELEGATION BUDGET regression: per_delegation unset -> child bounded only by the parent ceiling", async () => {
    const noPerDelegation = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 2
`;
    const fixedNow = 1_000_000_000;
    const { handler, log } = await makeEnv({
      policy: noPerDelegation,
      delegations: makeDelegations(),
      now: () => fixedNow,
    });
    const { token: child } = await selfMint(handler, { actions: ["repo:read"] });

    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    const third = await send(handler, "GET", "/u/github/repos/o/r", { token: child });
    expect(third.status).toBe(429);
    // The PARENT ceiling fired, not a per-token one — unset means no new cap.
    expect(third.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    log.close();
  });
});

describe("agent scope", () => {
  // A first-class agent confined in grenz.yaml. The shared policy allows
  // repo:read / pr:create on ANY target, so a denial can come ONLY from the
  // agent's own scope on the axis under test.
  async function scopedConfig(scope: { actions?: string[]; targets?: string[] }): Promise<GrenzConfig> {
    return configSchema.parse({
      listen: { host: "127.0.0.1", port: 8787 },
      upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
      agents: [{ id: "claude-code", token_hash: await hashToken(TOKEN), ...scope }],
    });
  }

  test("in-scope target passes, out-of-scope target is denied", async () => {
    const config = await scopedConfig({ targets: ["/repos/acme/*"] });
    const { handler, log } = await makeEnv({ config });

    const inScope = await send(handler, "GET", "/u/github/repos/acme/app");
    expect(inScope.status).toBe(200);

    const outScope = await send(handler, "GET", "/u/github/repos/evil/secret");
    expect(outScope.status).toBe(403);
    expect(outScope.headers.get("x-grenz-reason")).toBe("agent_target_scope");
    expect(cap.count).toBe(1); // only the in-scope read reached upstream
    log.close();
  });

  test("no scope = unrestricted (back-compat)", async () => {
    const { handler, log } = await makeEnv(); // default agents carry no scope
    expect((await send(handler, "GET", "/u/github/repos/anywhere/at/all")).status).toBe(200);
    log.close();
  });

  test("in-scope action passes, out-of-scope action is denied (even where policy allows it)", async () => {
    // The agent is confined to repo:read only. The shared policy ALSO allows
    // pr:create, but this agent may not use it — the denial is agent scope, not
    // the policy. Same target for both, so only the action axis differs.
    const config = await scopedConfig({ actions: ["repo:read"] });
    const { handler, log } = await makeEnv({ config });

    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);

    const outScope = await send(handler, "POST", "/u/github/repos/o/r/pulls", { body: "{}" });
    expect(outScope.status).toBe(403);
    expect(outScope.headers.get("x-grenz-reason")).toBe("agent_action_scope");
    log.close();
  });

  test("action scope is checked before target scope (the more specific signal)", async () => {
    // Confined on BOTH axes. A pr:create to an out-of-target path is out of
    // scope on both; the action denial wins.
    const config = await scopedConfig({ actions: ["repo:read"], targets: ["/repos/acme/*"] });
    const { handler, log } = await makeEnv({ config });
    const res = await send(handler, "POST", "/u/github/repos/evil/x/pulls", { body: "{}" });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("agent_action_scope");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("a delegation can never exceed its ROOT agent's scope (target axis)", async () => {
    const config = await scopedConfig({ targets: ["/repos/acme/*"] });
    const { handler, log } = await makeEnv({ config, delegations: makeDelegations() });
    // Mint a sub-token asking for a BROADER target than its agent is confined
    // to. Minting is permissive; the agent scope (the root hop of the fold)
    // still gates every request, so the sub-token cannot reach outside acme/*.
    const res = await send(handler, "POST", "/delegate", {
      body: JSON.stringify({ actions: ["repo:read"], targets: ["/repos/*"] }),
    });
    expect(res.status).toBe(200);
    const child = ((await res.json()) as { token: string }).token;

    expect((await send(handler, "GET", "/u/github/repos/acme/app", { token: child })).status).toBe(200);
    const beyond = await send(handler, "GET", "/u/github/repos/evil/x", { token: child });
    expect(beyond.status).toBe(403);
    expect(beyond.headers.get("x-grenz-reason")).toBe("agent_target_scope");
    log.close();
  });

  test("a delegation can never exceed its ROOT agent's scope (action axis)", async () => {
    const config = await scopedConfig({ actions: ["repo:read"] });
    const { handler, log } = await makeEnv({ config, delegations: makeDelegations() });
    // The sub-token asks for pr:create — which the shared policy allows — but its
    // root agent is confined to repo:read, so the root hop gates it out.
    const res = await send(handler, "POST", "/delegate", {
      body: JSON.stringify({ actions: ["repo:read", "pr:create"] }),
    });
    expect(res.status).toBe(200);
    const child = ((await res.json()) as { token: string }).token;

    expect((await send(handler, "GET", "/u/github/repos/o/r", { token: child })).status).toBe(200);
    const beyond = await send(handler, "POST", "/u/github/repos/o/r/pulls", { token: child, body: "{}" });
    expect(beyond.status).toBe(403);
    expect(beyond.headers.get("x-grenz-reason")).toBe("agent_action_scope");
    log.close();
  });
});

describe("risk-adaptive step-up", () => {
  const STEP_UP_POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
step_up:
  window_seconds: 900
`;
  const NO_STEP_UP_POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
`;
  const fixedNow = 3_000_000_000_000;

  /** Seed N identical deny rows for an agent, all within the step-up window. */
  function seedDenials(log: RequestLog, agentId: string, count: number): void {
    for (let i = 0; i < count; i++) {
      log.record({
        ts: fixedNow,
        agentId,
        upstream: "github",
        tool: "github",
        action: "issue:update",
        method: "PATCH",
        target: "/repos/o/r/issues/9",
        decision: "deny",
        reason: "explicit_deny",
        forwarded: false,
        status: null,
        count: 0,
      });
    }
  }

  test("no step_up configured: a high-risk agent's allow is unaffected", async () => {
    const { handler, log } = await makeEnv({ policy: NO_STEP_UP_POLICY, now: () => fixedNow });
    seedDenials(log, "claude-code", 15); // would score "high" if step_up were on
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("step_up configured, risk low: still a plain allow", async () => {
    const { handler, log } = await makeEnv({ policy: STEP_UP_POLICY, now: () => fixedNow });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("step_up configured, risk elevated (not high): still a plain allow", async () => {
    const { handler, log } = await makeEnv({ policy: STEP_UP_POLICY, now: () => fixedNow });
    seedDenials(log, "claude-code", 5); // scores "elevated" (40), not "high"
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("step_up configured, risk high, no broker: approvals_unavailable (fail closed)", async () => {
    const { handler, log } = await makeEnv({ policy: STEP_UP_POLICY, now: () => fixedNow }); // no broker
    seedDenials(log, "claude-code", 15); // scores "high" (80)
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("step_up configured, risk high, broker present: approval tagged [risk:high], approving forwards", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ policy: STEP_UP_POLICY, broker, now: () => fixedNow });
    seedDenials(log, "claude-code", 15);
    const pending = send(handler, "GET", "/u/github/repos/o/r");
    const id = await waitForApproval(broker);
    const record = broker.get(id)!;
    expect(record.action).toBe("repo:read [risk:high]");
    expect(broker.approve(id, "test")).toBe(true);

    const res = await pending;
    expect(res.status).toBe(200);
    expect(cap.count).toBe(1);
    const row = log.recent(1)[0]!;
    expect(row.decision).toBe("allow");
    expect(row.reason).toBe("approval_granted");
    expect(row.action).toBe("repo:read"); // persisted log stays untagged (canonical action)
    log.close();
  });

  test("step_up configured, risk high, broker present, denied: 403, never forwarded", async () => {
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ policy: STEP_UP_POLICY, broker, now: () => fixedNow });
    seedDenials(log, "claude-code", 15);
    const pending = send(handler, "GET", "/u/github/repos/o/r");
    const id = await waitForApproval(broker);
    broker.deny(id, "test");

    const res = await pending;
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approval_denied");
    expect(cap.count).toBe(0);
    log.close();
  });
});

describe("just-in-time temporary grants", () => {
  const fixedNow = 4_000_000_000_000;

  test("no grant configured: a policy-denied action stays denied", async () => {
    const { handler, log } = await makeEnv({ now: () => fixedNow });
    const res = await send(handler, "DELETE", "/u/github/repos/o/r"); // repo:delete -> no_matching_allow
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("no_matching_allow");
    log.close();
  });

  test("a grant matching a no_matching_allow gap allows the request, logged as jit_grant", async () => {
    const grants = makeGrants();
    grants.mint({ agentId: "claude-code", actions: ["repo:delete"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const { handler, log } = await makeEnv({ grants, now: () => fixedNow });
    const res = await send(handler, "DELETE", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    const row = log.recent(1)[0]!;
    expect(row.reason).toBe("jit_grant");
    log.close();
  });

  test("a grant matching a require_approval action allows immediately, no approval created", async () => {
    const grants = makeGrants();
    grants.mint({ agentId: "claude-code", actions: ["issue:update"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const broker = new ApprovalBroker(10_000);
    const { handler, log } = await makeEnv({ grants, broker, now: () => fixedNow });
    const res = await send(handler, "PATCH", APPROVAL_PATH, { body: "{}" });
    expect(res.status).toBe(200);
    expect(broker.list().length).toBe(0); // never went through the approval broker
    const row = log.recent(1)[0]!;
    expect(row.reason).toBe("jit_grant");
    log.close();
  });

  test("a grant does NOT override an explicit deny", async () => {
    const grants = makeGrants();
    grants.mint({ agentId: "claude-code", actions: ["pr:merge"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const { handler, log } = await makeEnv({ grants, now: () => fixedNow });
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("an expired grant does not apply", async () => {
    const grants = makeGrants();
    grants.mint({
      agentId: "claude-code",
      actions: ["repo:delete"],
      ttlMs: 1000,
      reason: "hotfix",
      now: fixedNow - 5000, // expired well before fixedNow
    });
    const { handler, log } = await makeEnv({ grants, now: () => fixedNow });
    const res = await send(handler, "DELETE", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    log.close();
  });

  test("a grant cut short via the existing kill-switch stops applying mid-TTL", async () => {
    const grants = makeGrants();
    const g = grants.mint({ agentId: "claude-code", actions: ["repo:delete"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const revocations = makeRevocations();
    revocations.revoke(g.id, "changed my mind", fixedNow);
    const { handler, log } = await makeEnv({ grants, revocations, now: () => fixedNow });
    const res = await send(handler, "DELETE", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    log.close();
  });

  test("a grant for a different agent does not leak across agents", async () => {
    const grants = makeGrants();
    grants.mint({ agentId: "someone-else", actions: ["repo:delete"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const { handler, log } = await makeEnv({ grants, now: () => fixedNow });
    const res = await send(handler, "DELETE", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    log.close();
  });

  test("a JIT-granted allow is still re-upgraded by risk step-up when the agent is separately high-risk", async () => {
    const STEP_UP_POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
step_up:
  window_seconds: 900
`;
    const grants = makeGrants();
    grants.mint({ agentId: "claude-code", actions: ["repo:delete"], ttlMs: 60_000, reason: "hotfix", now: fixedNow });
    const { handler, log } = await makeEnv({ policy: STEP_UP_POLICY, grants, now: () => fixedNow });
    for (let i = 0; i < 15; i++) {
      log.record({
        ts: fixedNow,
        agentId: "claude-code",
        upstream: "github",
        tool: "github",
        action: "issue:update",
        method: "PATCH",
        target: "/repos/o/r/issues/9",
        decision: "deny",
        reason: "explicit_deny",
        forwarded: false,
        status: null,
        count: 0,
      });
    }
    const res = await send(handler, "DELETE", "/u/github/repos/o/r"); // repo:delete: no policy grant, but JIT-granted
    expect(res.status).toBe(403); // no broker configured here -> approvals_unavailable
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });
});

describe("just-in-time temporary grants (console admin API)", () => {
  const ADMIN = "admin-token-xyz";
  const adminReq = (path: string, method = "GET"): Request =>
    new Request(`http://grenz.local${path}`, { method, headers: { "x-grenz-admin": ADMIN } });

  test("admin can mint a grant, list it, and it takes effect on the next request", async () => {
    const grants = makeGrants();
    const { handler, log } = await makeEnv({ grants, adminToken: ADMIN });

    const minted = await handler(
      adminReq("/console/grants?agent=claude-code&actions=repo:delete&reason=hotfix", "POST"),
    );
    expect(minted.status).toBe(200);
    const body = (await minted.json()) as { grant_id: string; agent: string; actions: string[] };
    expect(body.agent).toBe("claude-code");
    expect(body.actions).toEqual(["repo:delete"]);

    const listed = (await (await handler(adminReq("/console/grants"))).json()) as {
      grants: Array<{ id: string; agent: string }>;
    };
    expect(listed.grants.length).toBe(1);
    expect(listed.grants[0]!.id).toBe(body.grant_id);

    const res = await send(handler, "DELETE", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    log.close();
  });

  test("minting for an unknown agent is rejected", async () => {
    const grants = makeGrants();
    const { handler, log } = await makeEnv({ grants, adminToken: ADMIN });
    const res = await handler(adminReq("/console/grants?agent=ghost&actions=repo:read", "POST"));
    expect(res.status).toBe(404);
    log.close();
  });
});

describe("shadow / observe mode", () => {
  test("shadow: a policy DENY is forwarded and logged as a would-block (shadow=true, count 0)", async () => {
    const { handler, log, emitted } = await makeEnv({ shadow: true });
    // pr:merge is `deny` in POLICY — would 403 normally.
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(200); // forwarded despite the deny
    expect(cap.count).toBe(1); // upstream really was called
    const row = log.recent(1)[0]!;
    expect(row.decision).toBe("deny"); // the TRUE verdict is logged
    expect(row.reason).toBe("explicit_deny");
    expect(row.forwarded).toBe(true);
    expect(row.shadow).toBe(true);
    expect(row.count).toBe(0); // observational, not billed
    expect(emitted.join("\n")).toContain("[shadow] would-deny");
    log.close();
  });

  test("shadow: a REQUIRE_APPROVAL action is forwarded without blocking on a broker", async () => {
    // No broker passed: without shadow this returns 403 approvals_unavailable.
    const { handler, log } = await makeEnv({ shadow: true });
    const res = await send(handler, "PATCH", "/u/github/repos/o/r/issues/5", { body: "{}" });
    expect(res.status).toBe(200);
    expect(cap.count).toBe(1);
    const row = log.recent(1)[0]!;
    expect(row.decision).toBe("require_approval");
    expect(row.reason).toBe("approval_required");
    expect(row.shadow).toBe(true);
    log.close();
  });

  test("shadow does NOT bypass a revoked token", async () => {
    const revocations = makeRevocations();
    revocations.revoke("claude-code", "risk:high", 1);
    const { handler, log } = await makeEnv({ shadow: true, revocations });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("shadow does NOT bypass DLP (secret in body still blocks)", async () => {
    const dlpPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [pr:create]
dlp:
  scan_bodies: true
  on_match: deny
`;
    const { handler, log } = await makeEnv({ policy: dlpPolicy, shadow: true });
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const res = await send(handler, "POST", "/u/github/repos/o/r/pulls", {
      body: JSON.stringify({ title: "x", body: `key: ${secret}` }),
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("dlp_secret_detected");
    expect(cap.count).toBe(0);
    log.close();
  });

  test("shadow does NOT bypass the budget cap", async () => {
    const budgetPolicy = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
budget:
  max_actions_per_hour: 2
`;
    const fixedNow = 1_700_000_000;
    const { handler, log } = await makeEnv({ policy: budgetPolicy, shadow: true, now: () => fixedNow });
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    expect((await send(handler, "GET", "/u/github/repos/o/r")).status).toBe(200);
    const third = await send(handler, "GET", "/u/github/repos/o/r");
    expect(third.status).toBe(429);
    expect(third.headers.get("x-grenz-reason")).toBe("budget_exceeded");
    log.close();
  });

  test("without shadow (default), a policy DENY still denies", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    expect(cap.count).toBe(0);
    log.close();
  });
});

describe("egress guard", () => {
  test("an off-origin outbound path is blocked before the credential is fetched", async () => {
    // mcp maps the action from the BODY, so a `//evil` path still maps to an
    // ALLOWED action and reaches the egress gate (which runs after policy).
    const { handler, log } = await makeEnv();
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_thing" } });
    const res = await send(handler, "POST", "/u/mcp//evil.com/x", { body });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("egress_blocked");
    expect(cap.count).toBe(0); // never forwarded
    log.close();
  });

  test("a cross-host redirect is returned, not followed; no credential reaches the target", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/github/repos/o/r/redirect");
    expect(res.status).toBe(302); // the 302 is passed back to the agent
    expect(cap.auth).toBe(`Bearer ${GITHUB_CRED}`); // the issuing upstream got the credential...
    expect(redirectHit.count).toBe(0); // ...and the redirect target was never contacted
    expect(redirectHit.auth).toBeNull();
    log.close();
  });

  test("a normal allowed request still forwards to the correct origin (no regression)", async () => {
    const { handler, log } = await makeEnv();
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(cap.count).toBe(1);
    expect(cap.auth).toBe(`Bearer ${GITHUB_CRED}`);
    log.close();
  });
});

describe("policy hot-reload (live read)", () => {
  const DENY_MERGE = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny: [pr:merge]
`;
  const ALLOW_MERGE = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, pr:merge]
`;

  test("dispatch reflects a reloaded policy without recreating the handler", async () => {
    const first = compilePolicyYaml(DENY_MERGE);
    if (!first.ok) throw new Error(first.error);
    const store = new PolicyStore(first.policy);
    const { handler, log } = await makeEnv({ policyStore: store });

    // Under the initial policy, pr:merge is denied.
    const before = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(before.status).toBe(403);
    expect(before.headers.get("x-grenz-reason")).toBe("explicit_deny");

    // Hot-swap to a policy that allows it — same handler instance.
    const outcome = store.reload(ALLOW_MERGE);
    expect(outcome.ok).toBe(true);

    const after = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(after.status).toBe(200);
    expect(cap.count).toBe(1);
    log.close();
  });
});

describe("prometheus /metrics", () => {
  const ADMIN = "admin-token-xyz";

  test("GET /metrics with the admin header returns Prometheus text", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const res = await handler(
      new Request("http://grenz.local/metrics", { headers: { "x-grenz-admin": ADMIN } }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; version=0.0.4");
    expect(await res.text()).toContain("grenz_decisions_total");
    log.close();
  });

  test("GET /metrics accepts the admin token as a Bearer token", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const res = await handler(
      new Request("http://grenz.local/metrics", { headers: { authorization: `Bearer ${ADMIN}` } }),
    );
    expect(res.status).toBe(200);
    log.close();
  });

  test("GET /metrics without a token is unauthorized", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const res = await handler(new Request("http://grenz.local/metrics"));
    expect(res.status).toBe(401);
    log.close();
  });

  test("signed-distribution gauges report the live running version + staleness", async () => {
    const state: PolicyDistributionState = { version: 9, digest: "aabbccddeeff", lastVerifiedPullAt: 1_000_000 };
    const { handler, log } = await makeEnv({
      adminToken: ADMIN,
      policyDistribution: state,
      now: () => 1_090_000, // 90s after the last verified pull
    });
    const body = await (
      await handler(new Request("http://grenz.local/metrics", { headers: { "x-grenz-admin": ADMIN } }))
    ).text();
    expect(body).toContain("grenz_policy_version 9");
    expect(body).toContain("grenz_policy_seconds_since_pull 90");
    // Read by reference: a refresh mid-process is visible on the next scrape.
    state.version = 10;
    const after = await (
      await handler(new Request("http://grenz.local/metrics", { headers: { "x-grenz-admin": ADMIN } }))
    ).text();
    expect(after).toContain("grenz_policy_version 10");
    log.close();
  });

  test("a local (unsigned) proxy reports version 0 and no staleness", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    const body = await (
      await handler(new Request("http://grenz.local/metrics", { headers: { "x-grenz-admin": ADMIN } }))
    ).text();
    expect(body).toContain("grenz_policy_version 0");
    expect(body).toContain("grenz_policy_seconds_since_pull 0");
    log.close();
  });

  test("counts reflect real allow/deny traffic", async () => {
    const { handler, log } = await makeEnv({ adminToken: ADMIN });
    await send(handler, "GET", "/u/github/repos/o/r"); // allow
    await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge"); // deny (pr:merge)
    const res = await handler(
      new Request("http://grenz.local/metrics", { headers: { "x-grenz-admin": ADMIN } }),
    );
    const body = await res.text();
    expect(body).toContain(`grenz_decisions_total{decision="allow"} 1`);
    expect(body).toContain(`grenz_decisions_total{decision="deny"} 1`);
    log.close();
  });
});

describe("response minimization (size caps)", () => {
  const CAP_POLICY = (onExceed: string) => `${POLICY}responses:
  - on: [repo:read]
    max_bytes: 10
    on_exceed: ${onExceed}
`;

  test("truncate: an allowed oversized read is capped, still 200", async () => {
    const { handler, log } = await makeEnv({ policy: CAP_POLICY("truncate") });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-response-limit")).toBe("10");
    expect((await res.arrayBuffer()).byteLength).toBe(10); // UPSTREAM_BODY is 34 bytes
    expect(cap.count).toBe(1); // the read WAS forwarded upstream
    log.close();
  });

  test("deny: a declared-length read over cap -> 413 response_too_large, no body", async () => {
    const { handler, log } = await makeEnv({ policy: CAP_POLICY("deny") });
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(413);
    expect(res.headers.get("x-grenz-reason")).toBe("response_too_large");
    const body = (await res.json()) as { error?: string };
    expect(body.error).toBe("response_too_large");
    log.close();
  });

  test("an uncapped action returns the full body", async () => {
    const { handler, log } = await makeEnv({ policy: POLICY }); // no responses block
    const res = await send(handler, "GET", "/u/github/repos/o/r");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-grenz-response-limit")).toBeNull();
    expect((await res.arrayBuffer()).byteLength).toBe(UPSTREAM_BODY.length);
    log.close();
  });

  test("the cap never turns a policy deny into an allow", async () => {
    // pr:merge is denied by POLICY; a responses cap on it must not forward it.
    const { handler, log } = await makeEnv({
      policy: `${POLICY}responses:\n  - on: ["pr:merge"]\n    max_bytes: 10\n`,
    });
    const res = await send(handler, "POST", "/u/github/repos/o/r/merges", { body: "{}" });
    expect(res.status).toBe(403);
    expect(cap.count).toBe(0); // never forwarded
    log.close();
  });
});

// --- Per-agent policy selection on the request path (Slice 1, Task 6) --------
//
// DEFAULT allows github pr:read, denies pr:merge, and carries a tripwire on
// issue:read. The CI profile flips the grants — allows pr:merge, denies pr:read
// — but the merge is GRANTS-ONLY (mirroring load.ts / PolicyStore.storeWithCi),
// so the merged ci profile still inherits the default's tripwire.
describe("per-agent policy selection", () => {
  const PA_DEFAULT_YAML = `
agent: default
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: ["pr:read"]
    deny: ["pr:merge"]
tripwires:
  - action: "issue:read"
`;
  // The CI profile's OWN source: grants only, no tripwires declared.
  const PA_CI_GRANTS_YAML = `
agent: ci
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: ["pr:merge"]
    deny: ["pr:read"]
`;
  const DENY_ALL_YAML = `
agent: closed
on_behalf_of: am@team.dev
grants: []
`;

  function compile(yaml: string): CompiledPolicy {
    const r = compilePolicyYaml(yaml);
    if (!r.ok) throw new Error(r.error);
    return r.policy;
  }

  /** A store whose default is PA_DEFAULT and whose "ci" profile is the default
   *  with ci's grants swapped in — the grants-only merge load.ts performs, which
   *  is why the ci profile still carries the default's tripwire. */
  function paStore(): PolicyStore {
    const def = compile(PA_DEFAULT_YAML);
    // The store performs the grants-only merge itself now (ci's grants over the
    // default), so it still carries the default's tripwire.
    return new PolicyStore(def, new Set(["ci"]), [{ name: "ci", policy: PA_CI_GRANTS_YAML }]);
  }

  /** Config with claude-code on the default (no profile) and ci-bot on `profile`.
   *  `profileName` is the top-level policy_profiles key the ci-bot agent references
   *  (must exist for config validation); `targets` optionally scopes ci-bot. */
  async function paConfig(opts?: {
    profileName?: string;
    ciTargets?: string[];
    includeCiBot?: boolean;
  }): Promise<GrenzConfig> {
    const profileName = opts?.profileName ?? "ci";
    const agents: unknown[] = [{ id: "claude-code", token_hash: await hashToken(TOKEN) }];
    if (opts?.includeCiBot !== false) {
      agents.push({
        id: "ci-bot",
        token_hash: await hashToken(CI_TOKEN),
        policy: profileName,
        ...(opts?.ciTargets ? { targets: opts.ciTargets } : {}),
      });
    }
    return configSchema.parse({
      listen: { host: "127.0.0.1", port: 8787 },
      upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
      policy_profiles: { [profileName]: { file: `profiles/${profileName}.yaml` } },
      agents,
    });
  }

  async function mintChild(
    handler: Env["handler"],
    body: object,
    token: string,
  ): Promise<{ token: string }> {
    const res = await send(handler, "POST", "/delegate", { token, body: JSON.stringify(body) });
    expect(res.status).toBe(200);
    return (await res.json()) as { token: string };
  }

  test("ci-profile agent uses ci's grants (both directions)", async () => {
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig(),
      policyStore: paStore(),
    });
    // pr:merge — DEFAULT denies it, ci ALLOWS it → forwarded (200).
    const merge = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: CI_TOKEN });
    expect(merge.status).toBe(200);
    // pr:read — DEFAULT allows it, ci DENIES it → explicit_deny (403).
    const read = await send(handler, "GET", "/u/github/repos/o/r/pulls/1", { token: CI_TOKEN });
    expect(read.status).toBe(403);
    expect(read.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("default-policy agent is unchanged", async () => {
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig(),
      policyStore: paStore(),
    });
    // claude-code has NO profile → the shared default: pr:read ALLOWED.
    expect((await send(handler, "GET", "/u/github/repos/o/r/pulls/1", { token: TOKEN })).status).toBe(200);
    // …and pr:merge DENIED by the default's explicit deny.
    const merge = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: TOKEN });
    expect(merge.status).toBe(403);
    expect(merge.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("profile inherits the default's protections (tripwire fires)", async () => {
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig(),
      policyStore: paStore(),
    });
    // The ci profile's YAML declares no tripwires, but the grants-only merge
    // carried the default's issue:read tripwire into it — a ci request to
    // issue:read still trips.
    const res = await send(handler, "GET", "/u/github/repos/o/r/issues/5", { token: CI_TOKEN });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");
    log.close();
  });

  test("delegation under a ci-profile root uses ci and still folds", async () => {
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig(),
      policyStore: paStore(),
      delegations: makeDelegations(),
    });
    // ci-bot (profile ci) mints a child scoped to pr:merge only.
    const { token: child } = await mintChild(handler, { actions: ["pr:merge"] }, CI_TOKEN);
    // The child's root snapshot is ci → pr:merge is ALLOWED (the default would
    // have denied it), proving the profile selection follows the snapshot.
    expect((await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: child })).status).toBe(200);
    // …and the delegation fold STILL gates: pr:read is outside the attenuation.
    const out = await send(handler, "GET", "/u/github/repos/o/r/pulls/1", { token: child });
    expect(out.status).toBe(403);
    expect(out.headers.get("x-grenz-reason")).toBe("delegation_scope");
    log.close();
  });

  test("a delegation whose root agent is REMOVED from config is cut off (fail closed)", async () => {
    const delegations = makeDelegations();
    const store = paStore();
    // Mint under a config that HAS ci-bot…
    const e1 = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig(),
      policyStore: store,
      delegations,
    });
    const { token: child } = await mintChild(e1.handler, { actions: ["pr:merge"] }, CI_TOKEN);
    // It works while the root exists.
    expect(
      (await send(e1.handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: child })).status,
    ).toBe(200);
    e1.log.close();
    // …then rebuild the handler with ci-bot REMOVED from config (same store +
    // same delegations). A sub-token is only ever a narrowing of its root, so
    // with the root gone there is nothing to attenuate from: 401, not a request
    // running with the root's scope widened to unrestricted.
    const e2 = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig({ includeCiBot: false }),
      policyStore: store,
      delegations,
    });
    const res = await send(e2.handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: child });
    expect(res.status).toBe(401);
    // Masked: the wire says invalid_token; the true reason stays operator-side.
    expect(await res.json()).toMatchObject({ error: "invalid_token", reason: "invalid_token" });
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token");
    e2.log.close();
  });

  test("stale-closed overrides a profile", async () => {
    const store = paStore();
    store.closeAll(compile(DENY_ALL_YAML)); // enter the fail-closed state
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig(),
      policyStore: store,
    });
    // ci allows pr:merge, but the closed slot overrides every profile → deny-all
    // (empty grants ⇒ no grant for the github tool at all).
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: CI_TOKEN });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("no_grant_for_tool");
    log.close();
  });

  test("scope glob wins over a permissive profile", async () => {
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      // ci-bot is confined to /repos/allowed/* by its agent target scope.
      config: await paConfig({ ciTargets: ["/repos/allowed/*"] }),
      policyStore: paStore(),
    });
    // ci ALLOWS pr:merge on any target, but the request target is out of the
    // agent's scope — agent_target_scope gates BEFORE the profile is selected.
    const res = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge", { token: CI_TOKEN });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("agent_target_scope");
    log.close();
  });

  test("unknown profile on the principal → agent_policy_unresolved (403)", async () => {
    // ci-bot references profile "ghost" (declared in config so it validates), but
    // the store holds only "ci" → policyFor("ghost") is null → deny.
    const { handler, log } = await makeEnv({
      policy: PA_DEFAULT_YAML,
      config: await paConfig({ profileName: "ghost" }),
      policyStore: paStore(),
    });
    const res = await send(handler, "GET", "/u/github/repos/o/r/pulls/1", { token: CI_TOKEN });
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("agent_policy_unresolved");
    log.close();
  });

  test("no store / no profiles → identical decision to deps.policy (backward-compat)", async () => {
    // No policyStore: the handler must decide from deps.policy exactly as before.
    const { handler, log } = await makeEnv({ policy: PA_DEFAULT_YAML });
    // pr:read allowed, pr:merge denied — the default policy, unchanged.
    expect((await send(handler, "GET", "/u/github/repos/o/r/pulls/1")).status).toBe(200);
    const merge = await send(handler, "PUT", "/u/github/repos/o/r/pulls/1/merge");
    expect(merge.status).toBe(403);
    expect(merge.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("createHandler throws when a profile-bearing agent has no policyStore", async () => {
    const config = configSchema.parse({
      listen: { host: "127.0.0.1", port: 8787 },
      upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
      policy_profiles: { ci: { file: "profiles/ci.yaml" } },
      agents: [{ id: "claude-code", token_hash: await hashToken(TOKEN), policy: "ci" }],
    });
    const log = new RequestLog(dbPath);
    // A profile-bearing agent with no policyStore would silently ignore the
    // profile — the embed guard must refuse to construct (fail closed).
    expect(() =>
      createHandler({
        config,
        policy: compile(PA_DEFAULT_YAML),
        vault: fullVault,
        log,
        emit: () => {},
      }),
    ).toThrow();
    log.close();
  });

  test("createHandler throws when a profile-bearing delegation has no policyStore", async () => {
    const config = configSchema.parse({
      listen: { host: "127.0.0.1", port: 8787 },
      upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
      // No agent declares `policy` — the agent half of the guard stays quiet.
      agents: [{ id: "ci", token_hash: await hashToken(TOKEN) }],
    });
    const log = new RequestLog(dbPath);
    const delegations = new DelegationStore(join(tmp, "delegations.json"));
    // A live delegation snapshotted a policyProfile at mint (e.g. minted while a
    // policyStore was configured, then re-embedded without one) — the guard must
    // still catch it, not just profile-bearing agents.
    await delegations.mint({
      parentAgentId: "ci",
      actions: ["pr:*"],
      ttlMs: 60_000,
      note: "",
      now: Date.now(),
      policyProfile: "ci-merge",
    });
    expect(() =>
      createHandler({
        config,
        policy: compile(PA_DEFAULT_YAML),
        vault: fullVault,
        log,
        delegations,
        emit: () => {},
      }),
    ).toThrow();
    log.close();
  });
});
