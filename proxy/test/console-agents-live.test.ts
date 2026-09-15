import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { AgentStore } from "../src/agents/store.ts";
import { Mutex } from "../src/util/mutex.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

const ADMIN = "admin-live-agents";
let SEED: string;
let fake: ReturnType<typeof Bun.serve>, fakeUrl: string;

beforeAll(() => {
  SEED = generateToken();
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

let tmp: string, configPath: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-live-agents-"));
  configPath = join(tmp, "grenz.yaml");
});

async function makeHandler() {
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { github: { type: "github", base_url: fakeUrl, credential: "github_token" } },
    agents: [{ id: "seed", token_hash: await hashToken(SEED) }],
  });
  // A grenz.yaml on disk for the mint to append to.
  writeFileSync(
    configPath,
    `listen:\n  host: 127.0.0.1\n  port: 8787\nupstreams:\n  github:\n    type: github\n    base_url: ${fakeUrl}\n    credential: github_token\nagents:\n  - id: seed\n    token_hash: ${await hashToken(SEED)}\n`,
  );
  const compiled = compilePolicyYaml(`agent: seed\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
  if (!compiled.ok) throw new Error(compiled.error);
  const log = new RequestLog(join(tmp, "r.db"));
  const handler = createHandler({
    config,
    agentStore: new AgentStore(config.agents),
    configPath,
    configWriteLock: new Mutex(),
    adminToken: ADMIN,
    policy: compiled.policy,
    vault,
    log,
  });
  return { handler, log };
}

const mint = (h: (r: Request) => Promise<Response>, id: string) =>
  h(
    new Request("http://127.0.0.1/console/agents", {
      method: "POST",
      headers: { "x-grenz-admin": ADMIN, "content-type": "application/json" },
      body: JSON.stringify({ id }),
    }),
  );
const act = (h: (r: Request) => Promise<Response>, token: string, method: string) =>
  h(new Request("http://grenz.local/u/github/repos/o/r", { method, headers: { authorization: `Bearer ${token}` } }));

describe("console-minted agent — live, and still policy-gated", () => {
  test("a token minted via the console authenticates immediately (no restart)", async () => {
    const { handler, log } = await makeHandler();
    const res = await mint(handler, "ci-bot");
    expect(res.status).toBe(201);
    const { token } = (await res.json()) as { token: string };

    // The brand-new token is a real identity: an allowed action forwards (200),
    // NOT a 401 invalid_token. Proof the AgentStore seam is live on the auth path.
    const allowed = await act(handler, token, "GET");
    expect(allowed.status).toBe(200);
    expect(allowed.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("deny-by-default: the minted agent is denied an action its policy never grants", async () => {
    const { handler, log } = await makeHandler();
    const { token } = (await (await mint(handler, "ci-bot")).json()) as { token: string };

    // repo:delete is not in the allow list → denied at the door, credential never touched.
    const denied = await act(handler, token, "DELETE");
    expect(denied.status).toBe(403);
    expect(denied.headers.get("x-grenz-decision")).toBe("deny");
    log.close();
  });

  test("the minted token never appears in the request log", async () => {
    const { handler, log } = await makeHandler();
    const { token } = (await (await mint(handler, "ci-bot")).json()) as { token: string };
    await act(handler, token, "GET");
    const rows = log.recent(50);
    expect(JSON.stringify(rows)).not.toContain(token);
    log.close();
  });
});
