import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";
import { FlowFactStore } from "../src/flow/facts.ts";

const GITHUB_CRED = "ghp_flow_secret";
let TOKEN: string;
let fake: ReturnType<typeof Bun.serve>;
let fakeUrl: string;

beforeAll(async () => {
  TOKEN = generateToken();
  fake = Bun.serve({
    port: 0,
    fetch: () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
  });
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
  tmp = await mkdtemp(join(tmpdir(), "grenz-flow-"));
});

async function makeHandler(policyYaml: string, opts?: { shadow?: boolean; flowFacts?: FlowFactStore }) {
  const compiled = compilePolicyYaml(policyYaml);
  if (!compiled.ok) throw new Error(compiled.error);
  const config = await buildConfig();
  const log = new RequestLog(join(tmp, "requests.db"));
  const flowFacts = opts?.flowFacts ?? new FlowFactStore();
  const handler = createHandler({
    config,
    policy: compiled.policy,
    vault,
    log,
    flowFacts,
    shadow: opts?.shadow,
  });
  return { handler, log, flowFacts };
}

function send(handler: (r: Request) => Promise<Response>, method: string, path: string) {
  return handler(
    new Request(`http://grenz.local${path}`, {
      method,
      headers: { authorization: `Bearer ${TOKEN}` },
    }),
  );
}

const READ = ["GET", "/u/github/repos/o/r"] as const; // -> repo:read (source)
const MERGE = ["PUT", "/u/github/repos/o/r/pulls/1/merge"] as const; // -> pr:merge (sink)

const DENY_FLOW = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
flows:
  - when: [repo:read]
    then: ["pr:merge"]
    effect: deny
`;

describe("taint-flow dispatch gate", () => {
  test("sink WITHOUT a prior source forwards normally", async () => {
    const { handler, log } = await makeHandler(DENY_FLOW);
    const res = await send(handler, ...MERGE);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("source THEN sink is denied by the flow (flow_denied 403)", async () => {
    const { handler, log } = await makeHandler(DENY_FLOW);
    const src = await send(handler, ...READ);
    expect(src.headers.get("x-grenz-decision")).toBe("allow"); // source forwards + taints
    const sink = await send(handler, ...MERGE);
    expect(sink.status).toBe(403);
    expect(sink.headers.get("x-grenz-decision")).toBe("deny");
    expect(sink.headers.get("x-grenz-reason")).toBe("flow_denied");
    log.close();
  });

  test("effect require_approval escalates (no broker -> approvals_unavailable)", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read, "pr:merge"]
flows:
  - when: [repo:read]
    then: ["pr:merge"]
    effect: require_approval
`);
    await send(handler, ...READ);
    const sink = await send(handler, ...MERGE);
    expect(sink.headers.get("x-grenz-reason")).toBe("approvals_unavailable");
    log.close();
  });

  test("an explicit-deny sink stays explicit_deny (gate never overwrites a deny)", async () => {
    const { handler, log } = await makeHandler(`
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
flows:
  - when: [repo:read]
    then: ["pr:merge"]
    effect: deny
`);
    await send(handler, ...READ);
    const sink = await send(handler, ...MERGE);
    expect(sink.status).toBe(403);
    expect(sink.headers.get("x-grenz-reason")).toBe("explicit_deny");
    log.close();
  });

  test("--shadow observes the flow deny but does not enforce it", async () => {
    const { handler, log } = await makeHandler(DENY_FLOW, { shadow: true });
    await send(handler, ...READ);
    const sink = await send(handler, ...MERGE);
    // Under shadow the flow deny is suppressed; the request forwards.
    expect(sink.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });
});
