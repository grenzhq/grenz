/**
 * Regression: an MCP batch must not buy its members a cheaper quorum.
 *
 * Dual-control (`quorum: {action: n}`) is the strictest thing a policy can say
 * about an action — n DISTINCT humans, no approval-memory shortcut. It used to
 * be read off `combine()`'s single representative action, which collapsed two
 * different ways:
 *
 *   1. combine() returns the FIRST require_approval member, so a later member
 *      needing 3 approvers settled on the first one's 1.
 *   2. An all-allow batch collapses to the synthetic label `batch:N`, which
 *      matches no quorum pattern at all — so anything a dynamic gate clamped to
 *      require_approval afterwards needed a single tap, whatever its members
 *      were.
 *
 * The quorum is now the MAX over every action the request actually performs.
 * Each case asserts the batch demands what its strictest member demands.
 */
import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { ApprovalBroker } from "../src/approvals/broker.ts";
import { PinStore } from "../src/pin/store.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

let TOKEN: string;
let fake: ReturnType<typeof Bun.serve>;
let fakeUrl: string;

beforeAll(() => {
  TOKEN = generateToken();
  fake = Bun.serve({ port: 0, fetch: () => new Response("ok", { status: 200 }) });
  fakeUrl = `http://127.0.0.1:${fake.port}`;
});
afterAll(() => fake.stop(true));

const vault: CredentialStore = {
  async get(k) {
    return k === "mcp_token" ? "mcp_secret_value" : undefined;
  },
  async keys() {
    return ["mcp_token"];
  },
};

async function buildConfig(): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { mcp: { type: "mcp", base_url: fakeUrl, credential: "mcp_token" } },
    agents: [{ id: "claude-code", token_hash: await hashToken(TOKEN) }],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-quorum-"));
});

/**
 * A handler whose approvals are denied the instant they are raised, so the
 * request never blocks. The quorum the proxy asked for is captured off the
 * record first — that number is what every case here is about.
 */
async function makeHandler(policyYaml: string) {
  const compiled = compilePolicyYaml(policyYaml);
  if (!compiled.ok) throw new Error(compiled.error);
  const log = new RequestLog(join(tmp, "requests.db"));
  const broker = new ApprovalBroker(5_000);
  const asked: number[] = [];
  const handler = createHandler({
    config: await buildConfig(),
    policy: compiled.policy,
    vault,
    log,
    broker,
    pinFacts: new PinStore(),
    notifier: {
      approvalRequested: async (record) => {
        asked.push(record.quorum);
        broker.deny(record.id, "test");
      },
      tripwireTripped: async () => {},
    },
  });
  return { handler, log, asked };
}

/** One JSON-RPC `tools/call` message. Target label: `tools/call <name>`. */
function call(name: string, id = 1): unknown {
  return { jsonrpc: "2.0", id, method: "tools/call", params: { name } };
}

function post(handler: (r: Request) => Promise<Response>, body: unknown) {
  return handler(
    new Request("http://grenz.local/u/mcp/", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}

describe("MCP batch: quorum is the strictest member's, not the representative's", () => {
  // Both actions need a human; `drop_db` needs three of them. combine() returns
  // whichever comes FIRST, so message order is the whole test.
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: []
    require_approval: ["call:*"]
quorum:
  "call:drop_db": 3
`;

  test("single message: the strict action asks for 3", async () => {
    const { handler, log, asked } = await makeHandler(YAML);
    await post(handler, call("drop_db"));
    expect(asked).toEqual([3]);
    log.close();
  });

  test("strict member LAST in the batch: still asks for 3 (was: 1)", async () => {
    const { handler, log, asked } = await makeHandler(YAML);
    await post(handler, [call("deploy", 1), call("drop_db", 2)]);
    expect(asked).toEqual([3]);
    log.close();
  });

  test("strict member FIRST: asks for 3 either way", async () => {
    const { handler, log, asked } = await makeHandler(YAML);
    await post(handler, [call("drop_db", 1), call("deploy", 2)]);
    expect(asked).toEqual([3]);
    log.close();
  });

  test("a batch with no strict member still asks for 1", async () => {
    const { handler, log, asked } = await makeHandler(YAML);
    await post(handler, [call("deploy", 1), call("restart", 2)]);
    expect(asked).toEqual([1]);
    log.close();
  });
});

describe("MCP batch: an all-allow batch clamped by a dynamic gate keeps its quorum", () => {
  // Every member is a plain ALLOW, so combine() collapses the request to the
  // synthetic label `batch:2` — which matches no quorum pattern. The pin gate
  // then clamps to require_approval. Reading the quorum off `batch:2` asked one
  // human to nod through two actions that each demand three.
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
pins:
  - key: "tools/call (.*)"
    on: ["call:*"]
    effect: require_approval
    within_seconds: 3600
quorum:
  "call:drop_db": 3
`;

  test("single message: pin-clamped, asks for 3", async () => {
    const { handler, log, asked } = await makeHandler(YAML);
    await post(handler, call("safe_read")); // establishes the pinned unit
    await post(handler, call("drop_db"));
    expect(asked).toEqual([3]);
    log.close();
  });

  test("batched: pin-clamped, still asks for 3 (was: 1)", async () => {
    const { handler, log, asked } = await makeHandler(YAML);
    await post(handler, call("safe_read"));
    await post(handler, [call("drop_db", 1), call("deploy", 2)]);
    expect(asked).toEqual([3]);
    log.close();
  });
});
