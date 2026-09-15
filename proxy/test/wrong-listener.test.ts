import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { DelegationStore } from "../src/delegate/store.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

let REAL: string, TRAP: string;
let fake: ReturnType<typeof Bun.serve>, fakeUrl: string;

beforeAll(async () => {
  REAL = generateToken();
  TRAP = generateToken();
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
    listen: { host: "127.0.0.1", port: 8787, socket: "run/agent.sock" },
    upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
    agents: [
      { id: "real", token_hash: await hashToken(REAL) },
      { id: "trap", token_hash: await hashToken(TRAP), decoy: true },
    ],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-wrong-listener-"));
});

/** `agentRoutesEnabled: false` models the ADMIN (TCP) listener in socket mode. */
async function makeHandler(agentRoutesEnabled: boolean) {
  const compiled = compilePolicyYaml(`agent: real\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!compiled.ok) throw new Error(compiled.error);
  const log = new RequestLog(join(tmp, "r.db"));
  const revocations = new RevocationStore(join(tmp, "rev.json"));
  const decoyTrips: string[] = [];
  const wrongTrips: string[] = [];
  const handler = createHandler({
    config: await buildConfig(),
    policy: compiled.policy,
    vault,
    log,
    revocations,
    delegations: new DelegationStore(join(tmp, "del.json")),
    agentRoutesEnabled,
    notifier: {
      approvalRequested: async () => {},
      decoyTripped: async (kind, actorId) => {
        decoyTrips.push(`${kind}:${actorId}`);
      },
      wrongListener: async (actorId, upstreamName) => {
        wrongTrips.push(`${actorId}:${upstreamName}`);
      },
    },
  });
  return { handler, log, revocations, decoyTrips, wrongTrips };
}

const get = (handler: (r: Request) => Promise<Response>, token: string) =>
  handler(
    new Request("http://grenz.local/u/github/repos/o/r", {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
    }),
  );

const delegate = (handler: (r: Request) => Promise<Response>, token: string) =>
  handler(
    new Request("http://grenz.local/delegate", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ actions: ["repo:read"] }),
    }),
  );

describe("wrong_listener (agent routes on the admin listener)", () => {
  test("an agent route on the admin listener is 403 wrong_listener, logged with the agent id", async () => {
    const { handler, log } = await makeHandler(false);
    const res = await get(handler, REAL);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("wrong_listener");
    const rows = log.recent(10);
    expect(rows.some((r) => r.reason === "wrong_listener" && r.agentId === "real")).toBe(true);
    log.close();
  });

  test("a valid token on the wrong listener notifies (theft signal) but is NEVER auto-revoked", async () => {
    const { handler, log, revocations, wrongTrips } = await makeHandler(false);
    await get(handler, REAL);
    expect(wrongTrips).toEqual(["real:github"]);
    // A merely misconfigured legitimate agent must not self-destruct.
    expect(revocations.isRevoked("real")).toBe(false);
    log.close();
  });

  test("repeat replays do not re-notify (dedup), but every one is still logged", async () => {
    const { handler, log, wrongTrips } = await makeHandler(false);
    await get(handler, REAL);
    await get(handler, REAL);
    await get(handler, REAL);
    expect(wrongTrips).toEqual(["real:github"]); // notified once
    expect(log.recent(10).filter((r) => r.reason === "wrong_listener").length).toBe(3);
    log.close();
  });

  test("a DECOY token on the wrong listener still trips its decoy gate", async () => {
    const { handler, log, revocations, decoyTrips, wrongTrips } = await makeHandler(false);
    const res = await get(handler, TRAP);
    // The decoy gate wins: masked 401, revoked, decoy-notified — not wrong_listener.
    expect(res.status).toBe(401);
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token");
    expect(revocations.isRevoked("trap")).toBe(true);
    expect(decoyTrips).toEqual(["token:trap"]);
    expect(wrongTrips).toEqual([]);
    expect(log.recent(10).some((r) => r.reason === "decoy_token")).toBe(true);
    log.close();
  });

  test("an unknown token on the wrong listener is still a plain 401 (no identity to report)", async () => {
    const { handler, log, wrongTrips } = await makeHandler(false);
    const res = await get(handler, "grenz_unknown");
    expect(res.status).toBe(401);
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token");
    expect(wrongTrips).toEqual([]);
    log.close();
  });

  test("/delegate is refused on the admin listener too, and the refusal is LOGGED", async () => {
    const { handler, log, wrongTrips } = await makeHandler(false);
    const res = await delegate(handler, REAL);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "wrong_listener" });
    // The notifier defaults to a no-op, so a theft signal that is only notified
    // and never recorded leaves no trace at all.
    expect(log.recent(10).some((r) => r.reason === "wrong_listener" && r.agentId === "real")).toBe(true);
    expect(wrongTrips).toEqual(["real:-"]);
    log.close();
  });

  test("a REVOKED agent on /delegate gets token_revoked — not wrong_listener", async () => {
    const { handler, log, revocations, wrongTrips } = await makeHandler(false);
    revocations.revoke("real", "operator cut it off", Date.now());
    const res = await delegate(handler, REAL);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "token_revoked" });
    // A cut-off agent must not learn the topology, and must not burn the
    // one-shot notify slot that a later genuine replay would need.
    expect(wrongTrips).toEqual([]);
    log.close();
  });

  test("a REVOKED agent on an agent route gets token_revoked — not wrong_listener", async () => {
    const { handler, log, revocations, wrongTrips } = await makeHandler(false);
    revocations.revoke("real", "operator cut it off", Date.now());
    const res = await get(handler, REAL);
    expect(res.headers.get("x-grenz-reason")).toBe("token_revoked");
    expect(wrongTrips).toEqual([]);
    log.close();
  });

  test("with agent routes enabled (the socket listener, and TCP-only mode) nothing changes", async () => {
    const { handler, log, wrongTrips } = await makeHandler(true);
    const res = await get(handler, REAL);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    expect(wrongTrips).toEqual([]);
    expect((await delegate(handler, REAL)).status).toBe(200);
    log.close();
  });
});
