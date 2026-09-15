/**
 * Regression: an MCP JSON-RPC batch must not launder a request past any
 * target-scoped gate.
 *
 * A batch of N>1 messages used to collapse every per-message target into the
 * synthetic literal `batch(N)`, which matches no real target glob — so a
 * target-scoped deny / require_approval / tripwire / response-cap / pin simply
 * did not fire when the same action was wrapped in a batch. The adapter now
 * carries a per-action `targets` array and every gate evaluates the real
 * (action, target) pairs.
 *
 * Each case here asserts the SAME verdict for the single-message form and the
 * batched form — that equivalence is the invariant.
 */
import { test, expect, describe, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../src/proxy/server.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { configSchema, type GrenzConfig } from "../src/config/schema.ts";
import { RequestLog } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { PinStore } from "../src/pin/store.ts";
import type { CredentialStore } from "../src/vault/store.ts";
import { generateToken, hashToken } from "../src/util/token.ts";

const MCP_CRED = "mcp_secret_value";
let TOKEN: string;
let fake: ReturnType<typeof Bun.serve>;
let fakeUrl: string;
/** Response body size the fake upstream returns, for the response-cap case. */
let bodyBytes = 8;

beforeAll(() => {
  TOKEN = generateToken();
  fake = Bun.serve({
    port: 0,
    fetch: () => new Response("x".repeat(bodyBytes), { status: 200 }),
  });
  fakeUrl = `http://127.0.0.1:${fake.port}`;
});
afterAll(() => fake.stop(true));

const vault: CredentialStore = {
  async get(k) {
    return k === "mcp_token" ? MCP_CRED : undefined;
  },
  async keys() {
    return ["mcp_token"];
  },
};

async function buildConfig(agentTargets?: string[]): Promise<GrenzConfig> {
  return configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: { mcp: { type: "mcp", base_url: fakeUrl, credential: "mcp_token" } },
    agents: [
      {
        id: "claude-code",
        token_hash: await hashToken(TOKEN),
        ...(agentTargets ? { targets: agentTargets } : {}),
      },
    ],
  });
}

let tmp: string;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-batch-"));
  bodyBytes = 8;
});

interface Tripped {
  agentId: string;
  action: string;
  target: string | null;
}

async function makeHandler(policyYaml: string, agentTargets?: string[]) {
  const compiled = compilePolicyYaml(policyYaml);
  if (!compiled.ok) throw new Error(compiled.error);
  const config = await buildConfig(agentTargets);
  const log = new RequestLog(join(tmp, "requests.db"));
  const revocations = new RevocationStore(join(tmp, "revocations.json"));
  const pinFacts = new PinStore();
  const tripped: Tripped[] = [];
  const handler = createHandler({
    config,
    policy: compiled.policy,
    vault,
    log,
    revocations,
    pinFacts,
    notifier: {
      approvalRequested: async () => {},
      tripwireTripped: async (agentId, action, target) => {
        tripped.push({ agentId, action, target });
      },
    },
  });
  return { handler, log, revocations, tripped, pinFacts };
}

/** One JSON-RPC `tools/call` message for `name`. Target label: `tools/call <name>`. */
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

/** The decision + reason the proxy reports, from the response headers. */
async function verdict(res: Response): Promise<{ decision: string | null; reason: string | null }> {
  return { decision: res.headers.get("x-grenz-decision"), reason: res.headers.get("x-grenz-reason") };
}

describe("MCP batch: a target-scoped DENY fires inside a batch", () => {
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
    deny:
      - action: "call:*"
        targets: ["tools/call delete_prod"]
`;

  test("single message: denied", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, call("delete_prod"));
    expect(await verdict(res)).toEqual({ decision: "deny", reason: "explicit_deny" });
    log.close();
  });

  test("wrapped in a batch: STILL denied (was: allowed)", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("delete_prod", 2)]);
    expect(await verdict(res)).toEqual({ decision: "deny", reason: "explicit_deny" });
    log.close();
  });

  test("a batch of only in-scope calls is still allowed", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("get_thing", 2)]);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });
});

describe("MCP batch: a target-scoped REQUIRE_APPROVAL fires inside a batch", () => {
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
    require_approval:
      - action: "call:*"
        targets: ["tools/call deploy"]
`;

  test("single message: not allowed outright (approval gate engages)", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, call("deploy"));
    expect(res.headers.get("x-grenz-decision")).not.toBe("allow");
    log.close();
  });

  test("wrapped in a batch: STILL not allowed outright (was: allowed)", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("deploy", 2)]);
    expect(res.headers.get("x-grenz-decision")).not.toBe("allow");
    log.close();
  });

  test("a batch with no matching target is NOT clamped (precision, not blanket)", async () => {
    // The previous fix passed `null` for any batch, which made EVERY scoped
    // overlay rule match — safe but noisy. Real targets keep it exact.
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("get_thing", 2)]);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });
});

describe("MCP batch: a target-scoped TRIPWIRE fires inside a batch", () => {
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
tripwires:
  - action: "call:*"
    targets: ["tools/call exfiltrate"]
    note: "off-limits"
`;

  test("single message: trips and revokes", async () => {
    const { handler, log, revocations, tripped } = await makeHandler(YAML);
    const res = await post(handler, call("exfiltrate"));
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");
    expect(revocations.isRevoked("claude-code")).toBe(true);
    expect(tripped[0]!.target).toBe("tools/call exfiltrate");
    log.close();
  });

  test("wrapped in a batch: STILL trips and revokes (was: silent pass)", async () => {
    const { handler, log, revocations, tripped } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("exfiltrate", 2)]);
    expect(res.headers.get("x-grenz-reason")).toBe("tripwire");
    expect(revocations.isRevoked("claude-code")).toBe(true);
    // The notifier names the REAL target that tripped, not `batch(2)`.
    expect(tripped[0]!.target).toBe("tools/call exfiltrate");
    log.close();
  });

  test("a batch that touches no wired target does not trip", async () => {
    const { handler, log, revocations } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("get_thing", 2)]);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    expect(revocations.isRevoked("claude-code")).toBe(false);
    log.close();
  });
});

describe("MCP batch: a target-scoped RESPONSE CAP applies inside a batch", () => {
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
responses:
  - on: ["call:*"]
    targets: ["tools/call dump"]
    max_bytes: 4
    on_exceed: deny
`;

  test("single message: oversized response refused", async () => {
    bodyBytes = 64;
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, call("dump"));
    expect(res.status).toBe(413);
    log.close();
  });

  test("wrapped in a batch: STILL refused (was: cap silently dropped)", async () => {
    bodyBytes = 64;
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("dump", 2)]);
    expect(res.status).toBe(413);
    log.close();
  });

  test("a batch touching no capped target is uncapped", async () => {
    bodyBytes = 64;
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("list_things", 1), call("get_thing", 2)]);
    expect(res.status).toBe(200);
    log.close();
  });
});

describe("MCP batch: agent target scope reads the real targets", () => {
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
`;

  test("a batch of in-scope calls is allowed (was: every batch denied)", async () => {
    const { handler, log } = await makeHandler(YAML, ["tools/call safe_*"]);
    const res = await post(handler, [call("safe_read", 1), call("safe_list", 2)]);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });

  test("a batch hiding one out-of-scope call is denied", async () => {
    const { handler, log } = await makeHandler(YAML, ["tools/call safe_*"]);
    const res = await post(handler, [call("safe_read", 1), call("danger_write", 2)]);
    expect(await verdict(res)).toEqual({ decision: "deny", reason: "agent_target_scope" });
    log.close();
  });
});

describe("MCP batch: the PIN gate sees the per-message units", () => {
  const YAML = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: mcp
    allow: ["*"]
pins:
  - on: ["call:*"]
    key: "tools/call ([a-z]+)_.*"
    within_seconds: 3600
    effect: deny
`;

  test("a session pinned to one unit cannot pivot via a batch", async () => {
    const { handler, log } = await makeHandler(YAML);
    // Establish the pin with a plain single-message call.
    expect((await post(handler, call("alpha_read"))).headers.get("x-grenz-decision")).toBe("allow");
    // Pivot to a different unit, hidden inside a batch.
    const res = await post(handler, [call("alpha_list", 1), call("beta_write", 2)]);
    expect(await verdict(res)).toEqual({ decision: "deny", reason: "pin_violation" });
    log.close();
  });

  test("a batch cannot pivot WITHIN itself either (two units in one request)", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("alpha_read", 1), call("beta_write", 2)]);
    expect(await verdict(res)).toEqual({ decision: "deny", reason: "pin_violation" });
    log.close();
  });

  test("a batch staying inside one unit is allowed", async () => {
    const { handler, log } = await makeHandler(YAML);
    const res = await post(handler, [call("alpha_read", 1), call("alpha_write", 2)]);
    expect(res.headers.get("x-grenz-decision")).toBe("allow");
    log.close();
  });
});
