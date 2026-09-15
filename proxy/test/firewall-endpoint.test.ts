import { test, expect, describe } from "bun:test";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { hashToken } from "../src/util/token.ts";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = "admin-token-firewall";

function compile() {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

function entry(over: Partial<LogEntry>): LogEntry {
  return {
    ts: 1000,
    agentId: "a",
    upstream: "github",
    tool: "github",
    action: "repo:read",
    method: "GET",
    target: "/repos/o/r",
    decision: "allow",
    reason: "explicit_allow",
    forwarded: true,
    status: 200,
    count: 1,
    ...over,
  };
}

async function make(tokenStore: TokenStore | null = null): Promise<{ deps: ConsoleDeps; log: RequestLog }> {
  const dir = await mkdtemp(join(tmpdir(), "grenz-fw-ep-"));
  const log = new RequestLog(join(dir, "r.db"));
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "a", token_hash: await hashToken("t") }],
  });
  return {
    deps: {
      log,
      broker: null,
      revocations: null,
      delegations: null,
      grants: null,
      agentIds: ["a"],
      adminToken: ADMIN,
      config,
      policy: compile(),
      canaryStore: null,
      tokenStore,
      breakGlass: null,
      now: () => 1000,
    },
    log,
  };
}

function get(d: ConsoleDeps, headers: Record<string, string> = { "x-grenz-admin": ADMIN }) {
  return handleConsole(
    new Request("http://127.0.0.1/console/firewall", { headers }),
    new URL("http://127.0.0.1/console/firewall"),
    d,
  );
}

interface FwEvent {
  reason: string;
  occurrences: number;
  defense: { kind: string; label: string; blurb: string } | null;
}

describe("GET /console/firewall", () => {
  test("returns only defense events, classified, newest-first", async () => {
    const { deps: d, log } = await make();
    log.record(entry({ ts: 1, reason: "explicit_allow", decision: "allow" }));
    log.record(entry({ ts: 2, reason: "tripwire", decision: "deny", forwarded: false, status: null, count: 0 }));
    log.record(entry({ ts: 3, reason: "explicit_allow", decision: "allow" }));
    const res = await get(d);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { events: FwEvent[] };
    expect(body.events).toHaveLength(1); // the two allows are NOT defenses
    expect(body.events[0]!.reason).toBe("tripwire");
    expect(body.events[0]!.defense!.kind).toBe("trap");
  });

  test("every returned event carries a non-null defense", async () => {
    const { deps: d, log } = await make();
    for (const reason of ["tripwire", "flow_denied", "pin_violation", "dlp_secret_detected", "explicit_deny"] as const) {
      log.record(entry({ reason, decision: "deny", forwarded: false, status: null, count: 0 }));
    }
    const body = (await (await get(d)).json()) as { events: FwEvent[] };
    expect(body.events.length).toBeGreaterThan(0);
    expect(body.events.every((e) => e.defense !== null)).toBe(true);
  });

  test("a log with only allows yields an empty feed", async () => {
    const { deps: d, log } = await make();
    log.record(entry({ reason: "explicit_allow", decision: "allow" }));
    const body = (await (await get(d)).json()) as { events: FwEvent[] };
    expect(body.events).toEqual([]);
  });

  test("coalesces a revoke flood but keeps the tripwire cause visible", async () => {
    const { deps: d, log } = await make();
    log.record(entry({ ts: 1, reason: "tripwire", decision: "deny", forwarded: false, status: null, count: 0 }));
    for (let i = 0; i < 20; i++) {
      log.record(entry({ ts: 2 + i, reason: "token_revoked", decision: "deny", forwarded: false, status: null, count: 0 }));
    }
    const body = (await (await get(d)).json()) as { events: FwEvent[] };
    expect(body.events).toHaveLength(2);
    expect(body.events[0]!.reason).toBe("token_revoked");
    expect(body.events[0]!.occurrences).toBe(20);
    expect(body.events[1]!.reason).toBe("tripwire");
  });

  test("a viewer-role token can read the feed (it is a GET)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "grenz-fw-tok-"));
    const store = new TokenStore(join(dir, "admin-tokens.json"));
    const { token } = await store.create("watcher", "viewer", 1000);
    const { deps: d, log } = await make(store);
    log.record(entry({ reason: "tripwire", decision: "deny", forwarded: false, status: null, count: 0 }));
    const res = await get(d, { "x-grenz-admin": token });
    expect(res.status).toBe(200);
    log.close();
  });

  test("requires an admin credential", async () => {
    const { deps: d } = await make();
    const res = await get(d, {});
    expect(res.status).toBe(401);
  });
});
