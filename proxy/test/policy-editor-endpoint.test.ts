import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { PolicyStore } from "../src/policy/store.ts";
import { PolicyHistoryStore } from "../src/policy/history-store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { hashToken } from "../src/util/token.ts";
import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = "admin-token-poledit";

const POLICY = `agent: claude-code
on_behalf_of: you@example.com
grants:
  - tool: github
    allow:
      - repo:read
    deny:
      - pr:merge
budget:
  # keep it modest
  max_actions_per_hour: 200
`;

let dir: string;
let policyPath: string;
let log: RequestLog;
let store: PolicyStore;
let history: PolicyHistoryStore;
let memoryCleared: number;

function compile(text: string) {
  const r = compilePolicyYaml(text);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

async function deps(over?: Partial<ConsoleDeps>): Promise<ConsoleDeps> {
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "claude-code", token_hash: await hashToken("t") }],
  });
  return {
    log,
    broker: null,
    revocations: null,
    delegations: null,
    grants: null,
    agentIds: ["claude-code"],
    adminToken: ADMIN,
    tokenStore: null,
    config,
    policy: store.current,
    canaryStore: null,
    breakGlass: null,
    policyStore: store,
    policyHistory: history,
    policyPath,
    policyEditable: true,
    approvalMemory: { clear: () => { memoryCleared++; } },
    now: () => 1000,
    ...over,
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-poledit-"));
  policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, POLICY);
  log = new RequestLog(join(dir, "r.db"));
  store = new PolicyStore(compile(POLICY));
  history = new PolicyHistoryStore(join(dir, "policy-history"));
  memoryCleared = 0;
});
afterEach(async () => {
  log.close();
  await rm(dir, { recursive: true, force: true });
});

function req(method: string, body?: unknown, headers: Record<string, string> = { "x-grenz-admin": ADMIN }) {
  return new Request("http://127.0.0.1/console/policy", {
    method,
    headers: { ...headers, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
}
const url = () => new URL("http://127.0.0.1/console/policy");

interface GetBody {
  editable: boolean;
  grants: Array<{ tool: string; allow: unknown[]; require_approval: unknown[]; deny: unknown[] }>;
  advancedSections: string[];
  digest: string;
}

describe("GET /console/policy", () => {
  test("returns editable grants + advanced sections + a digest", async () => {
    const res = await handleConsole(req("GET"), url(), await deps());
    expect(res.status).toBe(200);
    const b = (await res.json()) as GetBody;
    expect(b.editable).toBe(true);
    expect(b.grants).toHaveLength(1);
    expect(b.grants[0]!.tool).toBe("github");
    expect(b.grants[0]!.allow).toEqual(["repo:read"]);
    expect(b.grants[0]!.deny).toEqual(["pr:merge"]);
    expect(b.advancedSections).toEqual(["budget"]);
    expect(b.digest).toMatch(/^[a-f0-9]{64}$/);
  });

  test("a remote (managed) policy is read-only", async () => {
    const res = await handleConsole(req("GET"), url(), await deps({ policyEditable: false }));
    const b = (await res.json()) as GetBody;
    expect(b.editable).toBe(false);
    expect(b.grants).toEqual([]);
  });
});

describe("POST /console/policy", () => {
  async function digest(d: ConsoleDeps): Promise<string> {
    return ((await (await handleConsole(req("GET"), url(), d)).json()) as GetBody).digest;
  }

  test("a valid edit writes the file, hot-reloads, records history, clears memory", async () => {
    const d = await deps();
    const baseDigest = await digest(d);
    const res = await handleConsole(
      req("POST", {
        grants: [{ tool: "github", allow: ["repo:read", "pr:read"], require_approval: ["issue:update"], deny: ["pr:merge"] }],
        baseDigest,
      }),
      url(),
      d,
    );
    expect(res.status).toBe(200);
    // file changed on disk...
    const onDisk = readFileSync(policyPath, "utf8");
    expect(onDisk).toContain("pr:read");
    expect(onDisk).toContain("issue:update");
    // ...advanced section + its comment preserved...
    expect(onDisk).toContain("# keep it modest");
    // ...live policy hot-reloaded...
    expect(store.current.grants.get("github")).toBeDefined();
    // ...history captured, approval memory cleared.
    expect(history.list().length).toBeGreaterThanOrEqual(1);
    expect(memoryCleared).toBeGreaterThanOrEqual(1);
  });

  test("an INVALID proposal is rejected 400 and NOTHING is written (deny-by-default)", async () => {
    const d = await deps();
    const baseDigest = await digest(d);
    const before = readFileSync(policyPath, "utf8");
    // Two grants for the same tool → compile error (duplicate grant).
    const res = await handleConsole(
      req("POST", {
        grants: [
          { tool: "github", allow: ["repo:read"] },
          { tool: "github", allow: ["pr:read"] },
        ],
        baseDigest,
      }),
      url(),
      d,
    );
    expect(res.status).toBe(400);
    expect(readFileSync(policyPath, "utf8")).toBe(before); // file untouched
    expect(store.current.grants.get("github")!).toBeDefined(); // live policy untouched
    expect(memoryCleared).toBe(0);
  });

  test("dryRun validates without writing", async () => {
    const d = await deps();
    const before = readFileSync(policyPath, "utf8");
    const res = await handleConsole(
      req("POST", { grants: [{ tool: "github", allow: ["repo:read", "repo:write"] }], dryRun: true }),
      url(),
      d,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { valid?: boolean }).valid).toBe(true);
    expect(readFileSync(policyPath, "utf8")).toBe(before);
  });

  test("a stale baseDigest is refused 409 (no silent clobber)", async () => {
    const d = await deps();
    const res = await handleConsole(
      req("POST", { grants: [{ tool: "github", allow: ["repo:read"] }], baseDigest: "deadbeef" }),
      url(),
      d,
    );
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error?: string }).error).toBe("stale_edit");
  });

  test("a remote policy refuses writes 409", async () => {
    const res = await handleConsole(
      req("POST", { grants: [{ tool: "github", allow: ["repo:read"] }], baseDigest: "x" }),
      url(),
      await deps({ policyEditable: false }),
    );
    expect(res.status).toBe(409);
  });

  test("POST needs admin; a viewer token is forbidden", async () => {
    const tdir = await mkdtemp(join(tmpdir(), "grenz-poledit-tok-"));
    const ts = new TokenStore(join(tdir, "admin-tokens.json"));
    const { token } = await ts.create("watcher", "viewer", 1000);
    const d = await deps({ tokenStore: ts });
    const res = await handleConsole(
      req("POST", { grants: [], baseDigest: "x" }, { "x-grenz-admin": token }),
      url(),
      d,
    );
    expect(res.status).toBe(403);
    await rm(tdir, { recursive: true, force: true });
  });
});
