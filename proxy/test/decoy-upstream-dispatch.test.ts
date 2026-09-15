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

let TOKEN: string;
let fake: ReturnType<typeof Bun.serve>, fakeUrl: string;

beforeAll(async () => {
  TOKEN = generateToken();
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

// `honeypot` is a decoy upstream (no credential); `github` is real and granted.
async function buildConfig(): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {
      github: { type: "github", base_url: fakeUrl, credential: "github_token" },
      honeypot: { decoy: true, type: "mcp" },
    },
    agents: [{ id: "claude-code", token_hash: await hashToken(TOKEN) }],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-decoyup-"));
});

async function makeHandler(shadow = false) {
  // Grant only github:repo:read — the agent has NO grant for `honeypot`, so a
  // touch is a would-deny that must still trip.
  const compiled = compilePolicyYaml(`agent: claude-code\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!compiled.ok) throw new Error(compiled.error);
  const log = new RequestLog(join(tmp, "r.db"));
  const revocations = new RevocationStore(join(tmp, "rev.json"));
  const delegations = new DelegationStore(join(tmp, "del.json"));
  const trips: string[] = [];
  const handler = createHandler({
    config: await buildConfig(),
    policy: compiled.policy,
    vault,
    log,
    revocations,
    delegations,
    shadow,
    notifier: {
      approvalRequested: async () => {},
      decoyTripped: async (kind, actorId, up) => {
        trips.push(`${kind}:${actorId}:${up}`);
      },
    },
  });
  return { handler, log, revocations, delegations, trips };
}

function touch(handler: (r: Request) => Promise<Response>, token: string, method = "GET", path = "/u/honeypot/x") {
  return handler(new Request(`http://grenz.local${path}`, { method, headers: { authorization: `Bearer ${token}` } }));
}

describe("decoy-upstream dispatch gate", () => {
  test("touching a decoy upstream (no grant → would-deny) trips: 403, revoked, masked", async () => {
    const { handler, log, revocations, trips } = await makeHandler();
    const res = await touch(handler, TOKEN);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("no_matching_allow"); // masked
    expect(revocations.isRevoked("claude-code")).toBe(true);
    expect(trips).toEqual(["upstream:claude-code:honeypot"]);
    const rows = log.recent(10);
    expect(rows.some((r) => r.reason === "decoy_upstream" && r.upstream === "honeypot")).toBe(true);
    log.close();
  });

  test("a POST body is never read to trip (fires the same on GET and POST)", async () => {
    const { handler, log, revocations } = await makeHandler();
    const res = await touch(handler, TOKEN, "POST", "/u/honeypot/charge");
    expect(res.status).toBe(403);
    expect(revocations.isRevoked("claude-code")).toBe(true);
    log.close();
  });

  test("the trip fires under --shadow", async () => {
    const { handler, log, revocations } = await makeHandler(true);
    await touch(handler, TOKEN);
    expect(revocations.isRevoked("claude-code")).toBe(true);
    log.close();
  });

  test("a real granted upstream is unaffected", async () => {
    const { handler, log, revocations } = await makeHandler();
    const res = await touch(handler, TOKEN, "GET", "/u/github/repos/o/r");
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    expect(revocations.isRevoked("claude-code")).toBe(false);
    log.close();
  });

  test("a delegation touching a decoy CASCADES: the whole tree dies (root revoked)", async () => {
    // The marquee behavior. A decoy is deterministic compromise, so a raided
    // sub-token reaching for it doesn't just kill itself — it revokes the ROOT
    // agent, and every node in the tree checks the root id on its next request.
    const { handler, log, revocations, delegations } = await makeHandler();
    const { token: raidedTok } = await delegations.mint({
      parentAgentId: "claude-code",
      actions: ["repo:read"],
      ttlMs: 60_000,
      note: "raided sub-agent",
      now: Date.now(),
    });
    const { token: siblingTok, delegation: sibling } = await delegations.mint({
      parentAgentId: "claude-code",
      actions: ["repo:read"],
      ttlMs: 60_000,
      note: "sibling doing honest work",
      now: Date.now(),
    });

    const res = await touch(handler, raidedTok);
    expect(res.status).toBe(403);
    // Root revoked → the whole tree is cut, without a per-node revoke.
    expect(revocations.isRevoked("claude-code")).toBe(true);
    expect(revocations.isRevoked(sibling.id)).toBe(false); // sibling id not itself listed…

    // …but the sibling and the parent are both cut off at the kill-switch,
    // because each checks the (now-revoked) root id on every request.
    const siblingAfter = await touch(handler, siblingTok, "GET", "/u/github/repos/o/r");
    expect(siblingAfter.status).toBe(403);
    expect(siblingAfter.headers.get("x-grenz-reason")).toBe("token_revoked");
    const parentAfter = await touch(handler, TOKEN, "GET", "/u/github/repos/o/r");
    expect(parentAfter.status).toBe(403);
    expect(parentAfter.headers.get("x-grenz-reason")).toBe("token_revoked");

    // The revoke reason records WHICH sub-token tripped it.
    expect(revocations.get("claude-code")!.reason).toContain("via ");
    log.close();
  });
});
