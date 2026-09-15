import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { BreakGlassStore } from "../src/breakglass/store.ts";
import { ApprovalBroker } from "../src/approvals/broker.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

const CRED = "ghp_bg_secret";
let TOKEN: string;
let fake: ReturnType<typeof Bun.serve>;
let fakeUrl: string;
beforeAll(async () => {
  TOKEN = generateToken();
  fake = Bun.serve({ port: 0, fetch: () => new Response("{}", { status: 200 }) });
  fakeUrl = `http://127.0.0.1:${fake.port}`;
});
afterAll(() => fake.stop(true));

const vault: CredentialStore = {
  async get(k) {
    return k === "github_token" ? CRED : undefined;
  },
  async keys() {
    return ["github_token"];
  },
};
async function buildConfig(): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
    agents: [{ id: "claude-code", token_hash: await hashToken(TOKEN) }],
  });
}
// Policy DENIES pr:merge (explicit deny), allows repo:read.
const POLICY = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
`;
let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-bg-"));
});
function compile(y: string) {
  const r = compilePolicyYaml(y);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}
const MERGE = ["PUT", "/u/github/repos/o/r/pulls/1/merge"] as const; // pr:merge
function send(handler: (r: Request) => Promise<Response>, method: string, path: string) {
  return handler(new Request(`http://grenz.local${path}`, { method, headers: { authorization: `Bearer ${TOKEN}` } }));
}
async function waitForApproval(broker: ApprovalBroker): Promise<string> {
  for (let i = 0; i < 50; i++) {
    const p = broker.list();
    if (p.length) return p[0]!.id;
    await Bun.sleep(5);
  }
  throw new Error("no pending approval");
}

describe("break-glass dispatch", () => {
  test("without a window, a denied action stays denied", async () => {
    const log = new RequestLog(join(tmp, "a.db"));
    const handler = createHandler({ config: await buildConfig(), policy: compile(POLICY), vault, log });
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("a matching window turns the deny into a break_glass approval (settled by one approver, quorum 1)", async () => {
    const log = new RequestLog(join(tmp, "b.db"));
    const breakGlass = new BreakGlassStore(join(tmp, "bg.json"));
    const broker = new ApprovalBroker(10_000);
    breakGlass.pull({ agentId: "claude-code", actions: ["pr:merge"], quorum: 1, reason: "hotfix", pulledBy: "carol", ttlMs: 900_000, now: Date.now() });
    const handler = createHandler({ config: await buildConfig(), policy: compile(POLICY), vault, log, breakGlass, broker });
    const pending = send(handler, ...MERGE);
    const id = await waitForApproval(broker);
    broker.approveBy(id, "carol");
    const res = await pending;
    expect(res.status).toBe(200); // forwarded after the human tap
    log.close();
  });

  test("batch-collapse guard: a window scoped to a different action does NOT unlock the denied action", async () => {
    const log = new RequestLog(join(tmp, "c.db"));
    const breakGlass = new BreakGlassStore(join(tmp, "bg.json"));
    breakGlass.pull({ agentId: "claude-code", actions: ["issue:*"], quorum: 1, reason: "x", pulledBy: "carol", ttlMs: 900_000, now: Date.now() });
    const handler = createHandler({ config: await buildConfig(), policy: compile(POLICY), vault, log, breakGlass });
    const res = await send(handler, ...MERGE); // pr:merge not covered by issue:* window
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("a revoked agent stays cut off even with a matching window", async () => {
    const log = new RequestLog(join(tmp, "d.db"));
    const breakGlass = new BreakGlassStore(join(tmp, "bg.json"));
    const revocations = new RevocationStore(join(tmp, "rev.json"));
    revocations.revoke("claude-code", "test", Date.now());
    breakGlass.pull({ agentId: "claude-code", actions: ["pr:merge"], quorum: 1, reason: "x", pulledBy: "carol", ttlMs: 900_000, now: Date.now() });
    const handler = createHandler({ config: await buildConfig(), policy: compile(POLICY), vault, log, breakGlass, revocations });
    const res = await send(handler, ...MERGE);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    log.close();
  });

  test("break-glass suspends a closed schedule: an unlocked deny is not re-denied by schedule_closed", async () => {
    // pr:merge is engine-DENIED; a break-glass window unlocks it to an approval.
    // The schedule is closed with on_closed:deny — which would clamp the unlocked
    // approval back to a deny. Break-glass must suspend that clamp, so the request
    // stays on the approval path (approvals_unavailable, no broker) rather than
    // returning schedule_closed.
    const SCHED = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
schedule:
  timezone: UTC
  on_closed: deny
  windows:
    - days: [mon]
      start: "00:00"
      end: "00:01"
`;
    const log = new RequestLog(join(tmp, "f.db"));
    const breakGlass = new BreakGlassStore(join(tmp, "bg.json"));
    breakGlass.pull({ agentId: "claude-code", actions: ["pr:merge"], quorum: 1, reason: "x", pulledBy: "carol", ttlMs: 900_000, now: Date.now() });
    const closedTs = Date.UTC(2026, 6, 15, 12, 0, 0); // Wed — outside the tiny Monday window
    const handler = createHandler({ config: await buildConfig(), policy: compile(SCHED), vault, log, breakGlass, now: () => closedTs });
    const res = await send(handler, ...MERGE);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable"); // NOT schedule_closed
    log.close();
  });

  test("break-glass suspends first-use: an unlocked NOVEL action is not re-denied by first_use_denied", async () => {
    // The first-use gate now fires on any non-deny verdict (so a schedule clamp
    // can't swallow an `on_first: deny`). Break-glass must stay exempt: the
    // emergency action is novel by definition, and a human already pulled the
    // handle for exactly this action.
    const FU = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
first_use:
  on_first: deny
  only: ["pr:*"]
`;
    const log = new RequestLog(join(tmp, "g.db"));
    const breakGlass = new BreakGlassStore(join(tmp, "bg.json"));
    const broker = new ApprovalBroker(10_000);
    breakGlass.pull({ agentId: "claude-code", actions: ["pr:merge"], quorum: 1, reason: "hotfix", pulledBy: "carol", ttlMs: 900_000, now: Date.now() });
    const handler = createHandler({ config: await buildConfig(), policy: compile(FU), vault, log, breakGlass, broker });
    const pending = send(handler, ...MERGE);
    broker.approveBy(await waitForApproval(broker), "carol");
    const res = await pending;
    expect(res.status).toBe(200); // NOT 403 first_use_denied
    log.close();
  });

  test("no broker: a break_glass approval surfaces as approvals_unavailable (403), not a silent allow", async () => {
    const log = new RequestLog(join(tmp, "e.db"));
    const breakGlass = new BreakGlassStore(join(tmp, "bg.json"));
    breakGlass.pull({ agentId: "claude-code", actions: ["pr:merge"], quorum: 1, reason: "x", pulledBy: "carol", ttlMs: 900_000, now: Date.now() });
    const handler = createHandler({ config: await buildConfig(), policy: compile(POLICY), vault, log, breakGlass });
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });
});
