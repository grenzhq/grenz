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

const GITHUB_CRED = "ghp_trip_secret";
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
    return k === "github_token" ? GITHUB_CRED : undefined;
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

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-trip-"));
});

interface Tripped {
  agentId: string;
  action: string;
  target: string | null;
  note: string | null;
}

async function makeHandler(policyYaml: string) {
  const compiled = compilePolicyYaml(policyYaml);
  if (!compiled.ok) throw new Error(compiled.error);
  const config = await buildConfig();
  const log = new RequestLog(join(tmp, "requests.db"));
  const revocations = new RevocationStore(join(tmp, "revocations.json"));
  const delegations = new DelegationStore(join(tmp, "delegations.json"));
  const tripped: Tripped[] = [];
  const handler = createHandler({
    config,
    policy: compiled.policy,
    vault,
    log,
    revocations,
    delegations,
    notifier: {
      approvalRequested: async () => {},
      tripwireTripped: async (agentId, action, target, note) => {
        tripped.push({ agentId, action, target, note });
      },
    },
  });
  return { handler, log, revocations, delegations, tripped };
}

function send(handler: (r: Request) => Promise<Response>, method: string, path: string, token = TOKEN) {
  return handler(
    new Request(`http://grenz.local${path}`, {
      method,
      headers: { authorization: `Bearer ${token}` },
    }),
  );
}

const READ = ["GET", "/u/github/repos/o/r"] as const; // repo:read
const MERGE = ["PUT", "/u/github/repos/o/r/pulls/1/merge"] as const; // pr:merge

describe("tripwire dispatch", () => {
  test("attempting a tripwired (even allowed) action trips: 403 + agent revoked", async () => {
    const { handler, log, revocations, tripped } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "pr:merge"
    note: "merges are off-limits"
`);
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");
    expect(res.headers.get("x-grenz-hint")).toBe("merges are off-limits");
    expect(revocations.isRevoked("claude-code")).toBe(true);
    expect(tripped[0]!.action).toBe("pr:merge");
    log.close();
  });

  test("a note with a non-Latin1 char (em-dash) still returns a clean 403, not a 500", async () => {
    // Regression (found by dogfooding): an em-dash in the note set the
    // `x-grenz-hint` header, whose value must be Latin1 — the Response
    // constructor threw a TypeError, turning the tripwire 403 into a 500
    // internal_error. The header is now ASCII-folded; the body keeps the UTF-8.
    const { handler, log, revocations } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "pr:merge"
    note: "destructive — never allowed"
`);
    const res = await send(handler, ...MERGE);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");
    expect(res.headers.get("x-grenz-hint")).toBe("destructive - never allowed"); // folded
    const body = (await res.json()) as { hint?: string };
    expect(body.hint).toBe("destructive — never allowed"); // body keeps the em-dash
    expect(revocations.isRevoked("claude-code")).toBe(true);
    log.close();
  });

  test("after a trip, an unrelated request is cut off (token_revoked)", async () => {
    const { handler, log, revocations } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "pr:merge"
`);
    await send(handler, ...MERGE); // trip
    expect(revocations.isRevoked("claude-code")).toBe(true);
    const after = await send(handler, ...READ);
    expect(after.status).toBe(403);
    expect(after.headers.get("x-grenz-reason")).toBe("token_revoked");
    log.close();
  });

  test("a tripwire fires even on a policy-DENIED action", async () => {
    const { handler, log, revocations } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
tripwires:
  - action: "pr:merge"
`);
    const res = await send(handler, ...MERGE);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire"); // not explicit_deny
    expect(revocations.isRevoked("claude-code")).toBe(true);
    log.close();
  });

  test("a non-tripwired action is unaffected", async () => {
    const { handler, log, revocations } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "repo:delete"
`);
    const res = await send(handler, ...READ);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    expect(revocations.isRevoked("claude-code")).toBe(false);
    log.close();
  });
});

describe("tripwire cascade (delegated sub-tokens)", () => {
  async function mintChild(
    delegations: DelegationStore,
    actions: string[],
    note: string,
  ): Promise<{ token: string; id: string }> {
    const { token, delegation } = await delegations.mint({
      parentAgentId: "claude-code",
      actions,
      ttlMs: 60_000,
      note,
      now: Date.now(),
    });
    return { token, id: delegation.id };
  }

  test("default (cascade): a sub-token tripping a wire kills the whole tree", async () => {
    const { handler, log, revocations, delegations, tripped } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "pr:merge"
`);
    const raided = await mintChild(delegations, ["repo:read", "pr:merge"], "raided");
    const sibling = await mintChild(delegations, ["repo:read"], "honest sibling");

    const res = await send(handler, ...MERGE, raided.token);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");

    // Root revoked → the whole tree is cut. The notifier names the ACTOR.
    expect(revocations.isRevoked("claude-code")).toBe(true);
    expect(tripped[0]!.agentId).toBe(raided.id);
    expect(revocations.get("claude-code")!.reason).toContain(`via ${raided.id}`);

    // Sibling and parent are both cut at the kill-switch (they check the root id).
    const sibAfter = await send(handler, ...READ, sibling.token);
    expect(sibAfter.headers.get("x-grenz-reason")).toBe("token_revoked");
    const parentAfter = await send(handler, ...READ);
    expect(parentAfter.headers.get("x-grenz-reason")).toBe("token_revoked");
    log.close();
  });

  test("on_trip: leaf — only the tripping sub-token dies; parent and siblings live", async () => {
    const { handler, log, revocations, delegations } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
tripwires:
  - action: "pr:merge"
    on_trip: leaf
`);
    const raided = await mintChild(delegations, ["repo:read", "pr:merge"], "raided");
    const sibling = await mintChild(delegations, ["repo:read"], "honest sibling");

    const res = await send(handler, ...MERGE, raided.token);
    expect(res.status).toBe(403);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");

    // Only the leaf is revoked; the root survives.
    expect(revocations.isRevoked(raided.id)).toBe(true);
    expect(revocations.isRevoked("claude-code")).toBe(false);

    // Sibling and parent keep working — a real read is still allowed.
    expect((await send(handler, ...READ, sibling.token)).headers.get("x-grenz-decision")).toBe("allow");
    expect((await send(handler, ...READ)).headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });
});
