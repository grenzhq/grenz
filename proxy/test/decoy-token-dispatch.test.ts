import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
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
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
    agents: [
      { id: "real", token_hash: await hashToken(REAL) },
      { id: "trap", token_hash: await hashToken(TRAP), decoy: true },
    ],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-decoytok-"));
});

async function makeHandler(shadow = false) {
  const compiled = compilePolicyYaml(`agent: real\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!compiled.ok) throw new Error(compiled.error);
  const log = new RequestLog(join(tmp, "r.db"));
  const revocations = new RevocationStore(join(tmp, "rev.json"));
  const trips: string[] = [];
  const handler = createHandler({
    config: await buildConfig(),
    policy: compiled.policy,
    vault,
    log,
    revocations,
    shadow,
    notifier: {
      approvalRequested: async () => {},
      decoyTripped: async (kind, actorId) => {
        trips.push(`${kind}:${actorId}`);
      },
    },
  });
  return { handler, log, revocations, trips };
}

function get(handler: (r: Request) => Promise<Response>, token: string) {
  return handler(
    new Request("http://grenz.local/u/github/repos/o/r", {
      method: "GET",
      headers: { authorization: `Bearer ${token}` },
    }),
  );
}

describe("decoy-token dispatch gate", () => {
  test("presenting a decoy token: 401, revoked, notified once, masked as invalid_token", async () => {
    const { handler, log, revocations, trips } = await makeHandler();
    const res = await get(handler, TRAP);
    expect(res.status).toBe(401);
    expect(res.headers.get("x-grenz-reason")).toBe("invalid_token"); // masked
    expect(revocations.isRevoked("trap")).toBe(true);
    expect(trips).toEqual(["token:trap"]);
    // The log row records the TRUE reason.
    const rows = log.recent(10);
    expect(rows.some((r) => r.reason === "decoy_token" && r.agentId === "trap")).toBe(true);
    log.close();
  });

  test("the masked 401 is byte-identical to an unauthenticated invalid_token deny", async () => {
    const { handler, log } = await makeHandler();
    const decoyRes = await get(handler, TRAP);
    const bogusRes = await get(handler, "grenz_totally-unknown-token");
    expect(decoyRes.status).toBe(bogusRes.status);
    expect(decoyRes.headers.get("x-grenz-decision")).toBe(bogusRes.headers.get("x-grenz-decision"));
    expect(decoyRes.headers.get("x-grenz-reason")).toBe(bogusRes.headers.get("x-grenz-reason"));
    expect(await decoyRes.text()).toBe(await bogusRes.text());
    log.close();
  });

  test("a second probe is the identical 401 (never token_revoked) and does not re-notify", async () => {
    const { handler, log, trips } = await makeHandler();
    const first = await get(handler, TRAP);
    const second = await get(handler, TRAP);
    expect(second.status).toBe(401);
    expect(second.headers.get("x-grenz-reason")).toBe("invalid_token");
    expect(await first.text()).toBe(await second.text());
    expect(trips).toEqual(["token:trap"]); // fresh-dedup: notified once
    log.close();
  });

  test("the trip fires under --shadow (real enforcement, never shadowed)", async () => {
    const { handler, log, revocations } = await makeHandler(true);
    const res = await get(handler, TRAP);
    expect(res.status).toBe(401);
    expect(revocations.isRevoked("trap")).toBe(true);
    log.close();
  });

  test("a real token is unaffected", async () => {
    const { handler, log, revocations } = await makeHandler();
    const res = await get(handler, REAL);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    expect(revocations.isRevoked("real")).toBe(false);
    log.close();
  });
});
