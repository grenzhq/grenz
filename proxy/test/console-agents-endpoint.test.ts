import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { handleConsole, type ConsoleDeps } from "../src/proxy/console.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { AgentStore } from "../src/agents/store.ts";
import { Mutex } from "../src/util/mutex.ts";
import { TokenStore } from "../src/admin/token-store.ts";
import { configSchema, type AgentConfig } from "../src/config/schema.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { PolicyStore } from "../src/policy/store.ts";
import { hashToken } from "../src/util/token.ts";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ADMIN = "admin-token-agents";

const GRENZ_YAML = `# grenz.yaml — non-secret runtime config.
listen:
  host: 127.0.0.1
  port: 8787
upstreams:
  github:
    type: github
    base_url: http://x
    credential: github_token
agents:
  - id: claude-code
    token_hash: __HASH__
`;

let dir: string;
let configPath: string;
let log: RequestLog;
let store: AgentStore;
let emitted: string[];

function compile(text: string) {
  const r = compilePolicyYaml(text);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

async function baseConfig() {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
    agents: [{ id: "claude-code", token_hash: await hashToken("t") }],
  });
}

async function deps(over?: Partial<ConsoleDeps>): Promise<ConsoleDeps> {
  return {
    log,
    broker: null,
    revocations: null,
    delegations: null,
    grants: null,
    agentIds: store.current.map((a) => a.id),
    adminToken: ADMIN,
    tokenStore: null,
    config: await baseConfig(),
    policy: compile(`agent: claude-code\non_behalf_of: x\ngrants: []\n`),
    canaryStore: null,
    breakGlass: null,
    agentStore: store,
    configPath,
    configWriteLock: new Mutex(),
    emit: (line: string) => emitted.push(line),
    now: () => 1000,
    ...over,
  };
}

function post(id: unknown, token = ADMIN): Request {
  return new Request("http://127.0.0.1/console/agents", {
    method: "POST",
    headers: { "x-grenz-admin": token, "content-type": "application/json" },
    body: JSON.stringify({ id }),
  });
}
function postBody(body: unknown, token = ADMIN): Request {
  return new Request("http://127.0.0.1/console/agents", {
    method: "POST",
    headers: { "x-grenz-admin": token, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}
const URL_ = new URL("http://127.0.0.1/console/agents");

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-agents-"));
  configPath = join(dir, "grenz.yaml");
  writeFileSync(configPath, GRENZ_YAML.replace("__HASH__", await hashToken("t")));
  log = new RequestLog(join(dir, "requests.db"));
  store = new AgentStore((await baseConfig()).agents);
  emitted = [];
});
afterEach(async () => {
  log.close();
  await rm(dir, { recursive: true, force: true });
});

describe("POST /console/agents", () => {
  test("mints an agent: 201 + token, persisted to grenz.yaml, live in the store", async () => {
    const res = await handleConsole(post("ci-bot"), URL_, await deps());
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; token: string };
    expect(body.id).toBe("ci-bot");
    expect(typeof body.token).toBe("string");
    expect(body.token.length).toBeGreaterThan(0);
    expect(res.headers.get("cache-control")).toBe("no-store");

    // Live: the store now holds ci-bot, and its stored hash matches the returned
    // token — i.e. the token authenticates immediately, no restart.
    expect(store.has("ci-bot")).toBe(true);
    const live = store.current.find((a) => a.id === "ci-bot")!;
    expect(live.token_hash).toBe(await hashToken(body.token));
    expect(live.decoy).toBe(false);
    expect(live.expiresAtMs).toBeNull();

    // Persisted: grenz.yaml on disk now contains the new agent (survives restart).
    const yaml = await readFile(configPath, "utf8");
    expect(yaml).toContain("id: ci-bot");
    expect(yaml).toContain(await hashToken(body.token));
    expect(yaml).toContain("# grenz.yaml — non-secret runtime config."); // comments preserved
  });

  test("mints a SCOPED agent: targets persisted, live in the store, echoed back", async () => {
    const res = await handleConsole(
      postBody({ id: "reviewer-acme", targets: ["/repos/acme/*"] }),
      URL_,
      await deps(),
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; token: string; targets?: string[] };
    expect(body.targets).toEqual(["/repos/acme/*"]); // echoed so the CLI can show scope

    // Live: the agent authenticates immediately AND carries its scope.
    const live = store.current.find((a) => a.id === "reviewer-acme")!;
    expect(live.targets).toEqual(["/repos/acme/*"]);
    expect(live.token_hash).toBe(await hashToken(body.token));

    // Persisted: grenz.yaml now confines it (survives restart).
    const yaml = await readFile(configPath, "utf8");
    expect(yaml).toContain("id: reviewer-acme");
    expect(yaml).toContain("/repos/acme/*");

    // The scope shows in the operational line (never the token).
    expect(emitted.some((l) => l.includes("reviewer-acme") && l.includes("/repos/acme/*"))).toBe(true);
    for (const line of emitted) expect(line).not.toContain(body.token);
  });

  test("mints an ACTION-scoped agent: actions persisted, live, echoed", async () => {
    const res = await handleConsole(
      postBody({ id: "reader", actions: ["repo:read"], targets: ["/repos/acme/*"] }),
      URL_,
      await deps(),
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as { token: string; actions?: string[]; targets?: string[] };
    expect(body.actions).toEqual(["repo:read"]);
    expect(body.targets).toEqual(["/repos/acme/*"]);

    const live = store.current.find((a) => a.id === "reader")!;
    expect(live.actions).toEqual(["repo:read"]);
    expect(live.targets).toEqual(["/repos/acme/*"]);

    const yaml = await readFile(configPath, "utf8");
    expect(yaml).toContain("repo:read");
    expect(emitted.some((l) => l.includes("reader") && l.includes("repo:read"))).toBe(true);
    for (const line of emitted) expect(line).not.toContain(body.token);
  });

  test("an empty actions array → 400, nothing minted", async () => {
    const res = await handleConsole(postBody({ id: "reader", actions: [] }), URL_, await deps());
    expect(res.status).toBe(400);
    expect(store.has("reader")).toBe(false);
  });

  test("an unscoped mint stays unrestricted (no targets key echoed or stored)", async () => {
    const res = await handleConsole(post("ci-bot"), URL_, await deps());
    expect(res.status).toBe(201);
    const body = (await res.json()) as { targets?: string[] };
    expect(body.targets).toBeUndefined();
    expect(store.current.find((a) => a.id === "ci-bot")!.targets).toBeUndefined();
  });

  test("an empty targets array → 400, nothing minted (unset scope is `absent`, not `[]`)", async () => {
    const res = await handleConsole(postBody({ id: "ci-bot", targets: [] }), URL_, await deps());
    expect(res.status).toBe(400);
    expect(store.has("ci-bot")).toBe(false);
  });

  test("the raw token NEVER appears in any emitted log line", async () => {
    const res = await handleConsole(post("ci-bot"), URL_, await deps());
    const body = (await res.json()) as { token: string };
    expect(emitted.length).toBeGreaterThan(0); // it did emit an operational line
    for (const line of emitted) expect(line).not.toContain(body.token);
    expect(emitted.some((l) => l.includes("ci-bot") && l.includes("minted"))).toBe(true);
  });

  test("duplicate id → 409, no token, file unchanged", async () => {
    const before = await readFile(configPath, "utf8");
    const res = await handleConsole(post("claude-code"), URL_, await deps());
    expect(res.status).toBe(409);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.token).toBeUndefined();
    expect(await readFile(configPath, "utf8")).toBe(before);
  });

  test("malformed id → 400, no token, file unchanged", async () => {
    const before = await readFile(configPath, "utf8");
    for (const bad of ["-", "Has Space", "UPPER", "-lead", "x".repeat(65)]) {
      const res = await handleConsole(post(bad), URL_, await deps());
      expect(res.status).toBe(400);
      expect(((await res.json()) as Record<string, unknown>).token).toBeUndefined();
    }
    expect(await readFile(configPath, "utf8")).toBe(before);
  });

  test("no AgentStore → 409 agents_admin_disabled", async () => {
    const res = await handleConsole(post("ci-bot"), URL_, await deps({ agentStore: null }));
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("agents_admin_disabled");
  });

  test("unauthorized (no admin token) → 401, nothing minted", async () => {
    const req = new Request("http://127.0.0.1/console/agents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: "ci-bot" }),
    });
    const res = await handleConsole(req, URL_, await deps());
    expect(res.status).toBe(401);
    expect(store.has("ci-bot")).toBe(false);
  });

  test("viewer role → 403, nothing minted", async () => {
    const tokenStore = new TokenStore(join(dir, "admin-tokens.json"));
    const viewer = (await tokenStore.create("vic", "viewer", 1000)).token;
    const res = await handleConsole(post("ci-bot", viewer), URL_, await deps({ tokenStore }));
    expect(res.status).toBe(403);
    expect(store.has("ci-bot")).toBe(false);
  });

  test("mints a PROFILE-bearing agent: policy persisted, live, echoed", async () => {
    // grenz.yaml must define the profile (the running proxy loaded it into the
    // store), so the rewritten file round-trips through the strict schema.
    writeFileSync(
      configPath,
      GRENZ_YAML.replace("__HASH__", await hashToken("t")) +
        "policy_profiles:\n  ci-merge: { file: profiles/ci.yaml }\n",
    );
    const def = compile(`agent: x\non_behalf_of: y\ngrants: []\n`);
    const policyStore = new PolicyStore(def, new Set(["ci-merge"]), [
      { name: "ci-merge", policy: `agent: x\non_behalf_of: y\ngrants: []\n` },
    ]);
    const res = await handleConsole(
      postBody({ id: "ci", policy: "ci-merge" }),
      URL_,
      await deps({ policyStore }),
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; token: string; policy?: string };
    expect(body.policy).toBe("ci-merge"); // echoed so the CLI can show it

    const live = store.current.find((a) => a.id === "ci")!;
    expect(live.policy).toBe("ci-merge"); // authenticates with its profile immediately
    expect(live.token_hash).toBe(await hashToken(body.token));

    const yaml = await readFile(configPath, "utf8");
    expect(yaml).toContain("policy: ci-merge");
    // The rewritten config still loads (profile is defined in policy_profiles).
    const { parse } = await import("yaml");
    expect(configSchema.safeParse(parse(yaml)).success).toBe(true);
  });

  test("an unknown profile → 400 unknown_profile, nothing minted, file unchanged", async () => {
    const before = await readFile(configPath, "utf8");
    const def = compile(`agent: x\non_behalf_of: y\ngrants: []\n`);
    const policyStore = new PolicyStore(def, new Set(["ci-merge"]), [
      { name: "ci-merge", policy: `agent: x\non_behalf_of: y\ngrants: []\n` },
    ]);
    const res = await handleConsole(
      postBody({ id: "ci", policy: "ghost" }),
      URL_,
      await deps({ policyStore }),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("unknown_profile");
    expect(store.has("ci")).toBe(false);
    expect(await readFile(configPath, "utf8")).toBe(before);
  });

  test("a profile with no policyStore → 400 unknown_profile (fail closed), nothing minted", async () => {
    // No store ⇒ no live profiles ⇒ any named profile is unresolvable → refuse.
    const res = await handleConsole(postBody({ id: "ci", policy: "ci-merge" }), URL_, await deps());
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("unknown_profile");
    expect(store.has("ci")).toBe(false);
  });

  test("two concurrent same-id mints → exactly one 201, and grenz.yaml still loads", async () => {
    const d = await deps(); // shares one Mutex + one store across both calls
    const [a, b] = await Promise.all([
      handleConsole(post("ci-bot"), URL_, d),
      handleConsole(post("ci-bot"), URL_, d),
    ]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([201, 409]);
    // The file still parses under the strict schema — no torn/duplicate write.
    const { parse } = await import("yaml");
    const parsed = configSchema.safeParse(parse(await readFile(configPath, "utf8")));
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.agents.filter((x: AgentConfig) => x.id === "ci-bot")).toHaveLength(1);
    }
  });
});

describe("GET /console/agents", () => {
  function get(token = ADMIN): Request {
    return new Request("http://127.0.0.1/console/agents", {
      method: "GET",
      headers: { "x-grenz-admin": token },
    });
  }

  test("lists live agents with id/policy/actions/targets/expiry — never a token hash", async () => {
    // Seed a profiled + scoped agent into the live store.
    const seeded = configSchema.parse({
      upstreams: { github: { type: "github", base_url: "http://x", credential: "github_token" } },
      policy_profiles: { "ci-merge": { file: "profiles/ci.yaml" } },
      agents: [
        { id: "claude-code", token_hash: await hashToken("t") },
        { id: "ci", token_hash: await hashToken("u"), policy: "ci-merge", actions: ["pr:merge"], targets: ["acme/*"] },
      ],
    });
    store = new AgentStore(seeded.agents);

    const res = await handleConsole(get(), URL_, await deps());
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      agents: Array<{ id: string; policy: string | null; actions: string[]; targets: string[]; expires_at: string | null }>;
    };
    const ci = body.agents.find((a) => a.id === "ci")!;
    expect(ci.policy).toBe("ci-merge");
    expect(ci.actions).toEqual(["pr:merge"]);
    expect(ci.targets).toEqual(["acme/*"]);
    const legacy = body.agents.find((a) => a.id === "claude-code")!;
    expect(legacy.policy).toBeNull();
    // No secret material anywhere in the response.
    const raw = JSON.stringify(body);
    expect(raw).not.toContain(await hashToken("t"));
    expect(raw).not.toContain(await hashToken("u"));
    expect(raw.toLowerCase()).not.toContain("token_hash");
  });

  test("unauthorized (no admin token) → 401", async () => {
    const req = new Request("http://127.0.0.1/console/agents", { method: "GET" });
    const res = await handleConsole(req, URL_, await deps());
    expect(res.status).toBe(401);
  });
});
