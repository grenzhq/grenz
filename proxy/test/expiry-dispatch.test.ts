import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { DelegationStore } from "../src/delegate/store.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

// Injected clock so expiry is deterministic (no reliance on the real date).
const NOW = Date.parse("2026-07-19T12:00:00Z");
const PAST = "2026-07-18T00:00:00Z"; // < NOW → expired
const FUTURE = "2026-08-01T00:00:00Z"; // > NOW → live

let LIVE: string, DEAD: string;
let fake: ReturnType<typeof Bun.serve>, fakeUrl: string;

beforeAll(async () => {
  LIVE = generateToken();
  DEAD = generateToken();
  fake = Bun.serve({ port: 0, fetch: () => new Response("{}", { status: 200 }) });
  fakeUrl = `http://127.0.0.1:${fake.port}`;
});
afterAll(() => fake.stop(true));

const vault: CredentialStore = {
  async get(k) {
    return k === "github_token" ? "ghp_secret" : undefined;
  },
  async keys() {
    return ["github_token"];
  },
};

async function buildConfig(): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
    agents: [
      { id: "real", token_hash: await hashToken(LIVE), expires_at: FUTURE },
      { id: "lapsed", token_hash: await hashToken(DEAD), expires_at: PAST },
    ],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-expiry-"));
});

async function makeHandler() {
  const compiled = compilePolicyYaml(`agent: real\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!compiled.ok) throw new Error(compiled.error);
  const log = new RequestLog(join(tmp, "r.db"));
  const handler = createHandler({
    config: await buildConfig(),
    policy: compiled.policy,
    vault,
    log,
    delegations: new DelegationStore(join(tmp, "del.json")),
    now: () => NOW,
  });
  return { handler, log };
}

function get(handler: (r: Request) => Promise<Response>, token: string) {
  return handler(
    new Request("http://grenz.local/u/github/repos/o/r", {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
    }),
  );
}

describe("agent-token-expiry dispatch gate", () => {
  test("an expired agent: 401, masked as invalid_token, log row agent_token_expired with the id", async () => {
    const { handler, log } = await makeHandler();
    const res = await get(handler, DEAD);
    expect(res.status).toBe(401);
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token"); // masked
    const rows = log.recent(10);
    expect(rows.some((r) => r.reason === "agent_token_expired" && r.agentId === "lapsed")).toBe(true);
    log.close();
  });

  test("the masked 401 is byte-identical to an unknown-token invalid_token deny", async () => {
    const { handler, log } = await makeHandler();
    const expiredRes = await get(handler, DEAD);
    const bogusRes = await get(handler, "grenz_totally-unknown-token");
    expect(expiredRes.status).toBe(bogusRes.status);
    expect(expiredRes.headers.get("x-grenz-decision")).toBe(bogusRes.headers.get("x-grenz-decision"));
    expect(expiredRes.headers.get("x-grenz-reason")).toBe(bogusRes.headers.get("x-grenz-reason"));
    expect(await expiredRes.text()).toBe(await bogusRes.text());
    log.close();
  });

  test("a live (unexpired) agent is unaffected", async () => {
    const { handler, log } = await makeHandler();
    const res = await get(handler, LIVE);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("an expired agent cannot mint a delegation (/delegate is 401, never a sub-token)", async () => {
    const { handler, log } = await makeHandler();
    const mint = (token: string) =>
      handler(
        new Request("http://grenz.local/delegate", {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ actions: ["repo:read"] }),
        }),
      );
    const dead = await mint(DEAD);
    expect(dead.status).toBe(401);
    expect(await dead.json()).toEqual({ error: "invalid_token" });
    // The live agent still mints, so the 401 is expiry — not a broken endpoint.
    expect((await mint(LIVE)).status).toBe(200);
    log.close();
  });
});
