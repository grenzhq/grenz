import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { CanaryStore } from "../src/canary/store.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

const GITHUB_CRED = "ghp_canary_secret";
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
  tmp = await mkdtemp(join(tmpdir(), "grenz-canary-"));
});

const LIVE = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
`;

function compile(yaml: string) {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

async function makeHandler(candidateYaml: string | null) {
  const config = await buildConfig();
  const log = new RequestLog(join(tmp, "requests.db"));
  const canaryStore = candidateYaml ? new CanaryStore() : undefined;
  const handler = createHandler({
    config,
    policy: compile(LIVE),
    vault,
    log,
    canaryPolicy: candidateYaml ? compile(candidateYaml) : undefined,
    canaryStore,
  });
  return { handler, log, canaryStore };
}

function read(handler: (r: Request) => Promise<Response>) {
  return handler(
    new Request("http://grenz.local/u/github/repos/o/r", {
      method: "GET",
      headers: { authorization: `Bearer ${TOKEN}` },
    }),
  );
}

describe("canary dispatch", () => {
  test("candidate denying repo:read records a stricter divergence; live still allows", async () => {
    const { handler, log, canaryStore } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: []
    deny: [repo:read]
`);
    const res = await read(handler);
    expect(res.status).toBe(200); // live policy still allows -> forwarded
    const snap = canaryStore!.snapshot();
    expect(snap.requests).toBe(1);
    expect(snap.divergences).toBe(1);
    expect(snap.rows[0]).toMatchObject({
      tool: "github",
      action: "repo:read",
      live: "allow",
      candidate: "deny",
      direction: "stricter",
    });
    log.close();
  });

  test("identical candidate records zero divergences", async () => {
    const { handler, log, canaryStore } = await makeHandler(LIVE);
    await read(handler);
    const snap = canaryStore!.snapshot();
    expect(snap.requests).toBe(1);
    expect(snap.divergences).toBe(0);
    log.close();
  });

  test("no canary configured -> no crash, request still served", async () => {
    const { handler, log } = await makeHandler(null);
    const res = await read(handler);
    expect(res.status).toBe(200);
    log.close();
  });
});
