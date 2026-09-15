/**
 * `grenz demo-cascade` — watch one tripped decoy kill an entire agent swarm, in
 * ~1 second, entirely in-process. A lead agent spawns two sub-agents, each with
 * its own scoped sub-token. One sub-agent is raided and reaches for a
 * honeytoken; the instant it does, the WHOLE tree — the lead and every sibling —
 * is revoked. No real credentials (the github upstream is a loopback stub, the
 * vault holds a dummy value); nothing is left on disk. The outcome demonstrated
 * on the user's own machine against a real policy, not claimed.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../proxy/server.ts";
import { compilePolicyYaml } from "../policy/compile.ts";
import { configSchema } from "../config/schema.ts";
import { RequestLog } from "../log/request-log.ts";
import { RevocationStore } from "../revoke/store.ts";
import { DelegationStore } from "../delegate/store.ts";
import { generateToken, hashToken } from "../util/token.ts";
import type { CredentialStore } from "../vault/store.ts";
import type { ParsedArgs } from "./args.ts";

const LEAD = "lead-agent";

// A safe-default-shaped policy: reads allowed for the lead. The honeypot
// upstream has no grant on purpose — touching it is high-confidence compromise,
// and a decoy always cascades.
const POLICY = `
agent: ${LEAD}
on_behalf_of: demo@grenz.dev
grants:
  - tool: github
    allow: [repo:read, pr:read, issue:read]
`;

export async function runDemoCascade(_args: ParsedArgs): Promise<number> {
  const compiled = compilePolicyYaml(POLICY);
  if (!compiled.ok) {
    process.stderr.write("grenz: demo policy failed to compile\n");
    return 1;
  }

  const fake = Bun.serve({ port: 0, fetch: () => new Response("{}", { status: 200 }) });
  const tmp = await mkdtemp(join(tmpdir(), "grenz-cascade-"));
  const leadToken = generateToken();
  const vault: CredentialStore = {
    async get(k) {
      return k === "github_token" ? "dummy-not-a-real-token" : undefined;
    },
    async keys() {
      return ["github_token"];
    },
  };
  const config = configSchema.parse({
    listen: { host: "127.0.0.1", port: 8787 },
    upstreams: {
      github: { type: "github", base_url: `http://127.0.0.1:${fake.port}`, credential: "github_token" },
      honeypot: { decoy: true, type: "github" },
    },
    agents: [{ id: LEAD, token_hash: await hashToken(leadToken) }],
  });
  const log = new RequestLog(join(tmp, "requests.db"));
  const revocations = new RevocationStore(join(tmp, "revocations.json"));
  const delegations = new DelegationStore(join(tmp, "delegations.json"));
  const handler = createHandler({
    config,
    policy: compiled.policy,
    vault,
    log,
    revocations,
    delegations,
    notifier: { approvalRequested: async () => {}, decoyTripped: async () => {} },
    emit: () => {}, // silence the proxy's internal log lines — this demo narrates its own
  });

  // The lead spawns two sub-agents, each a strictly narrower sub-token.
  const now = Date.now();
  const { token: reviewerToken } = await delegations.mint({
    parentAgentId: LEAD,
    actions: ["repo:read"],
    ttlMs: 900_000,
    note: "reviewer",
    now,
  });
  const { token: runnerToken } = await delegations.mint({
    parentAgentId: LEAD,
    actions: ["repo:read"],
    ttlMs: 900_000,
    note: "test-runner (about to be raided)",
    now,
  });

  const act = async (who: string, what: string, token: string, method: string, path: string) => {
    const res = await handler(
      new Request(`http://grenz.local${path}`, { method, headers: { authorization: `Bearer ${token}` } }),
    );
    const dec = res.headers.get("x-grenz-decision") ?? "?";
    const reason = res.headers.get("x-grenz-reason") ?? "";
    process.stdout.write(`  ${who.padEnd(13)} ${what.padEnd(24)} ${dec.padEnd(6)} ${reason}\n`);
  };

  process.stdout.write("\n  Grenz — one tripped decoy kills the whole swarm\n");
  process.stdout.write("  ===============================================\n");
  process.stdout.write("  A lead agent spawned two sub-agents, each with its own scoped sub-token.\n\n");
  process.stdout.write("  WHO           DOES                     DECISION WHY\n");

  process.stdout.write("  -- the swarm is working normally --\n");
  await act("lead", "read a repo", leadToken, "GET", "/u/github/repos/o/r");
  await act("reviewer", "read a repo", reviewerToken, "GET", "/u/github/repos/o/r");
  await act("test-runner", "read a repo", runnerToken, "GET", "/u/github/repos/o/r");

  process.stdout.write("  -- the test-runner is raided; it reaches for the honeytoken --\n");
  await act("test-runner", "grab the honeytoken", runnerToken, "GET", "/u/honeypot/anything");

  process.stdout.write("  -- one trip. now the ENTIRE tree is dead --\n");
  await act("test-runner", "try anything", runnerToken, "GET", "/u/github/repos/o/r");
  await act("reviewer", "try anything", reviewerToken, "GET", "/u/github/repos/o/r");
  await act("lead", "try anything", leadToken, "GET", "/u/github/repos/o/r");

  process.stdout.write(
    "\n  The reviewer never misbehaved. The lead never misbehaved. But one sub-agent\n" +
      "  touching the decoy revoked the ROOT — and every token in the tree checks the\n" +
      "  root at the door, so the whole swarm was cut off at once, in well under a\n" +
      "  second. No real credentials were used; nothing was left on disk.\n\n",
  );

  log.close();
  fake.stop(true);
  await rm(tmp, { recursive: true, force: true });
  return 0;
}
