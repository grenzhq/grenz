import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { PinStore } from "../src/pin/store.ts";
import { DelegationStore } from "../src/delegate/store.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

const CRED = "ghp_pin_secret";
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

// PATCH /repos/o/r/issues/1 -> issue:update ; GET -> issue:read.
const POLICY = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: ["issue:*"]
pins:
  - key: "^/repos/([^/]+/[^/]+)"
    on: ["issue:update"]
`;

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-pin-"));
});

function compile(yaml: string) {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

function write(handler: (r: Request) => Promise<Response>, repo: string, token = TOKEN) {
  return handler(
    new Request(`http://grenz.local/u/github/repos/${repo}/issues/1`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${token}` },
    }),
  );
}
function read(handler: (r: Request) => Promise<Response>, repo: string) {
  return handler(
    new Request(`http://grenz.local/u/github/repos/${repo}/issues/1`, {
      method: "GET",
      headers: { authorization: `Bearer ${TOKEN}` },
    }),
  );
}

describe("pin dispatch", () => {
  test("first write pins; same-repo write is free; a new repo escalates", async () => {
    const config = await buildConfig();
    const log = new RequestLog(join(tmp, "a.db"));
    const handler = createHandler({ config, policy: compile(POLICY), vault, log, pinFacts: new PinStore() });
    expect((await write(handler, "acme/api")).status).toBe(200); // first write -> pins acme/api
    expect((await write(handler, "acme/api")).status).toBe(200); // same repo -> free
    const pivot = await write(handler, "acme/payroll"); // new repo -> require_approval
    // No broker -> require_approval surfaces as 403 approvals_unavailable (vs the
    // 200 allow the same-repo writes got) — proof the pin gate escalated.
    expect(pivot.status).toBe(403);
    expect(pivot.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("reads are never gated by pins", async () => {
    const config = await buildConfig();
    const log = new RequestLog(join(tmp, "b.db"));
    const handler = createHandler({ config, policy: compile(POLICY), vault, log, pinFacts: new PinStore() });
    await write(handler, "acme/api"); // pin acme/api
    expect((await read(handler, "acme/payroll")).status).toBe(200); // read elsewhere -> free
    log.close();
  });

  test("effect: deny returns pin_violation 403 on pivot", async () => {
    const config = await buildConfig();
    const log = new RequestLog(join(tmp, "c.db"));
    const handler = createHandler({
      config,
      policy: compile(POLICY.replace(`on: ["issue:update"]`, `on: ["issue:update"]\n    effect: deny`)),
      vault,
      log,
      pinFacts: new PinStore(),
    });
    await write(handler, "acme/api");
    const pivot = await write(handler, "acme/payroll");
    expect(pivot.status).toBe(403);
    expect(pivot.headers.get("x-grenz-reason")).toBe("pin_violation");
    log.close();
  });

  test("a delegation inherits its parent's pin (cannot escape via a fresh delegationId)", async () => {
    const config = await buildConfig();
    const log = new RequestLog(join(tmp, "d.db"));
    const delegations = new DelegationStore(join(tmp, "del.json"));
    const handler = createHandler({ config, policy: compile(POLICY), vault, log, pinFacts: new PinStore(), delegations });
    await write(handler, "acme/api"); // parent pins acme/api
    const { token: childToken } = await delegations.mint({
      parentAgentId: "claude-code",
      actions: ["issue:*"],
      ttlMs: 60_000,
      note: "",
      now: Date.now(),
    });
    // Child writes to a DIFFERENT repo -> inherits parent's pin -> escalates.
    const pivot = await write(handler, "acme/payroll", childToken);
    expect(pivot.status).toBe(403);
    expect(pivot.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    // Child writes to the SAME repo the parent pinned -> free.
    expect((await write(handler, "acme/api", childToken)).status).toBe(200);
    log.close();
  });
});
