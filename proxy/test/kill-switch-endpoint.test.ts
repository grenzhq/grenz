import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { PolicyStore } from "../src/policy/store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import type { FleetRevocationStore } from "../src/revocation/store.ts";
import { configSchema } from "../src/config/schema.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = "admin-token-killswitch";
const AGENTS = ["claude-code", "release-bot"];

const POLICY = `agent: claude-code
on_behalf_of: you@example.com
grants:
  - tool: github
    allow:
      - repo:read
`;

let dir: string;
let log: RequestLog;
let store: PolicyStore;
let revocations: RevocationStore;

function compile(text: string) {
  const r = compilePolicyYaml(text);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

/** A minimal fleet kill-set stub: only `has()` is consulted by the endpoint. */
function fleetStub(ids: string[]): FleetRevocationStore {
  const set = new Set(ids);
  return { has: (id: string) => set.has(id) } as unknown as FleetRevocationStore;
}

async function deps(over?: Partial<ConsoleDeps>): Promise<ConsoleDeps> {
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: AGENTS.map((id, i) => ({ id, token_hash: String.fromCharCode(97 + i).repeat(64) })),
  });
  return {
    log,
    broker: null,
    revocations,
    delegations: null,
    grants: null,
    agentIds: AGENTS,
    adminToken: ADMIN,
    tokenStore: null,
    config,
    policy: store.current,
    canaryStore: null,
    breakGlass: null,
    policyStore: store,
    now: () => 1000,
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-killswitch-"));
  log = new RequestLog(join(dir, "r.db"));
  store = new PolicyStore(compile(POLICY));
  revocations = new RevocationStore(join(dir, "revocations.json"));
});
afterEach(async () => {
  log.close();
  await rm(dir, { recursive: true, force: true });
});

function req(method: string, headers: Record<string, string> = { "x-grenz-admin": ADMIN }) {
  return new Request("http://127.0.0.1/console/revocations", { method, headers });
}
const url = () => new URL("http://127.0.0.1/console/revocations");

interface AgentRow {
  id: string;
  revoked: boolean;
  local: boolean;
  fleet: boolean;
  reason?: string;
  ts?: number;
  origin?: "auto" | "manual";
}
interface OtherRow {
  id: string;
  reason: string;
  ts: number;
  origin: "auto" | "manual";
}
interface Body {
  enabled: boolean;
  revocations: unknown[];
  agents: AgentRow[];
  other: OtherRow[];
}

async function read(d: ConsoleDeps): Promise<Body> {
  const res = await handleConsole(req("GET"), url(), d);
  expect(res.status).toBe(200);
  return (await res.json()) as Body;
}
const agent = (b: Body, id: string) => b.agents.find((a) => a.id === id)!;

describe("GET /console/revocations — enriched kill-switch view", () => {
  test("no revocations: every configured agent is active, nothing else", async () => {
    const b = await read(await deps());
    expect(b.enabled).toBe(true);
    expect(b.agents).toHaveLength(2);
    for (const a of b.agents) {
      expect(a.revoked).toBe(false);
      expect(a.local).toBe(false);
      expect(a.fleet).toBe(false);
    }
    expect(b.other).toEqual([]);
  });

  test("a manual revocation of a configured agent shows on its row", async () => {
    revocations.revoke("release-bot", "risk:high", 1000);
    const b = await read(await deps());
    const bot = agent(b, "release-bot");
    expect(bot.revoked).toBe(true);
    expect(bot.local).toBe(true);
    expect(bot.origin).toBe("manual");
    expect(bot.reason).toBe("risk:high");
    expect(bot.ts).toBe(1000);
    expect(agent(b, "claude-code").revoked).toBe(false);
  });

  test("a top-level agent auto-revoked (decoy) is classified auto and stays in agents", async () => {
    // For a top-level agent the decoy/tripwire session key IS its agent id.
    revocations.revoke("claude-code", "decoy: token presented", 1000);
    const b = await read(await deps());
    const cc = agent(b, "claude-code");
    expect(cc.revoked).toBe(true);
    expect(cc.origin).toBe("auto");
    // ...and it must NOT leak into the id-not-configured list.
    expect(b.other.find((o) => o.id === "claude-code")).toBeUndefined();
  });

  test("a revocation of a non-agent id (delegation/session key) lands in `other`", async () => {
    revocations.revoke("claude-code#dlg-abc", "tripwire: pr:merge", 1000);
    const b = await read(await deps());
    expect(b.agents.every((a) => !a.revoked)).toBe(true);
    expect(b.other).toHaveLength(1);
    expect(b.other[0]!.id).toBe("claude-code#dlg-abc");
    expect(b.other[0]!.origin).toBe("auto");
  });

  test("a fleet-only agent (in the signed set, no local record) reads as revoked", async () => {
    const b = await read(await deps({ fleetRevocations: fleetStub(["release-bot"]) }));
    const bot = agent(b, "release-bot");
    expect(bot.revoked).toBe(true);
    expect(bot.local).toBe(false);
    expect(bot.fleet).toBe(true);
    expect(bot.reason).toBeUndefined();
  });

  test("an agent revoked then removed from config appears in `other`, not agents", async () => {
    revocations.revoke("retired-bot", "risk:high", 1000);
    const b = await read(await deps()); // agentIds is still [claude-code, release-bot]
    expect(b.agents.find((a) => a.id === "retired-bot")).toBeUndefined();
    expect(b.other.find((o) => o.id === "retired-bot")).toBeDefined();
  });

  test("a disabled store reports enabled:false with empty lists", async () => {
    const b = await read(await deps({ revocations: null }));
    expect(b.enabled).toBe(false);
    expect(b.agents).toEqual([]);
    expect(b.other).toEqual([]);
  });
});

describe("kill-switch mutations remain admin-gated", () => {
  test("a viewer token cannot revoke (403)", async () => {
    const tdir = await mkdtemp(join(tmpdir(), "grenz-ks-tok-"));
    const ts = new TokenStore(join(tdir, "admin-tokens.json"));
    const { token } = await ts.create("watcher", "viewer", 1000);
    const d = await deps({ tokenStore: ts });
    const res = await handleConsole(
      new Request("http://127.0.0.1/console/revocations/release-bot", {
        method: "POST",
        headers: { "x-grenz-admin": token },
      }),
      new URL("http://127.0.0.1/console/revocations/release-bot"),
      d,
    );
    expect(res.status).toBe(403);
    await rm(tdir, { recursive: true, force: true });
  });

  test("revoke then restore flips the agent row", async () => {
    const d = await deps();
    await handleConsole(
      new Request("http://127.0.0.1/console/revocations/release-bot?reason=manual", { method: "POST", headers: { "x-grenz-admin": ADMIN } }),
      new URL("http://127.0.0.1/console/revocations/release-bot?reason=manual"),
      d,
    );
    expect(agent(await read(d), "release-bot").revoked).toBe(true);
    await handleConsole(
      new Request("http://127.0.0.1/console/revocations/release-bot", { method: "DELETE", headers: { "x-grenz-admin": ADMIN } }),
      new URL("http://127.0.0.1/console/revocations/release-bot"),
      d,
    );
    expect(agent(await read(d), "release-bot").revoked).toBe(false);
  });
});
