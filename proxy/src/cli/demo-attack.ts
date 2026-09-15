/**
 * `grenz demo-attack` — watch Grenz stop a rogue agent, in ~1 second, entirely
 * in-process. No real credentials (the github upstream points at a loopback
 * stub and the vault holds a dummy value); nothing is left on disk. Proof on the
 * user's own machine, against a real policy — the outcome demonstrated, not claimed.
 *
 * The demo is framed to answer the first objection everyone raises: "why not
 * just scope the GitHub token tightly?" A scoped token still (a) merges a PR the
 * instant an agent is told to, (b) is the agent's to leak, and (c) can only be
 * killed by regenerating it at GitHub. Grenz answers all three — approval on an
 * in-scope action, the credential never leaving the proxy, and an instant local
 * revoke — and this demo shows each one happening, not asserted.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHandler } from "../proxy/server.ts";
import { compilePolicyYaml } from "../policy/compile.ts";
import { configSchema } from "../config/schema.ts";
import { RequestLog } from "../log/request-log.ts";
import { RevocationStore } from "../revoke/store.ts";
import { ApprovalBroker } from "../approvals/broker.ts";
import { generateToken, hashToken } from "../util/token.ts";
import type { CredentialStore } from "../vault/store.ts";
import type { ParsedArgs } from "./args.ts";

const AGENT = "rogue-agent";

// A realistic safe-default-shaped policy: reads flow, but merging a PR — an
// action a repo-scoped PAT is perfectly allowed to do — is held for a human.
const POLICY = `
agent: ${AGENT}
on_behalf_of: demo@grenz.dev
grants:
  - tool: github
    allow: [repo:read, pr:read, issue:read]
    require_approval: [pr:merge]
`;

export async function runDemoAttack(_args: ParsedArgs): Promise<number> {
  const compiled = compilePolicyYaml(POLICY);
  if (!compiled.ok) {
    process.stderr.write("grenz: demo policy failed to compile\n");
    return 1;
  }

  const fake = Bun.serve({ port: 0, fetch: () => new Response("{}", { status: 200 }) });
  const tmp = await mkdtemp(join(tmpdir(), "grenz-demo-"));
  const token = generateToken();
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
    },
    agents: [{ id: AGENT, token_hash: await hashToken(token) }],
  });
  const log = new RequestLog(join(tmp, "requests.db"));
  const revocations = new RevocationStore(join(tmp, "revocations.json"));
  const broker = new ApprovalBroker(5 * 60_000);
  const handler = createHandler({
    config,
    policy: compiled.policy,
    vault,
    log,
    revocations,
    broker,
    notifier: { approvalRequested: async () => {}, tripwireTripped: async () => {} },
    emit: () => {}, // silence the proxy's internal log lines — this demo narrates its own
  });

  // Fire a request and print its verdict. Returns the promise so a caller can
  // leave it in-flight (a require_approval request blocks until decided below).
  const act = (what: string, method: string, path: string): Promise<void> =>
    handler(
      new Request(`http://grenz.local${path}`, { method, headers: { authorization: `Bearer ${token}` } }),
    ).then((res) => {
      const dec = res.headers.get("x-grenz-decision") ?? "?";
      const reason = res.headers.get("x-grenz-reason") ?? "";
      process.stdout.write(`  ${what.padEnd(36)} ${dec.padEnd(6)} ${reason}\n`);
    });

  // Wait until the in-flight request has registered its pending approval, then
  // let the "operator" decide it — mirrors a human hitting `grenz deny <id>`.
  const decidePending = async (decide: (id: string) => void): Promise<void> => {
    for (let i = 0; i < 1000 && broker.list().length === 0; i++) {
      await new Promise((r) => setTimeout(r, 0));
    }
    const rec = broker.list()[0];
    if (rec) decide(rec.id);
  };

  process.stdout.write("\n  Grenz — what a scoped token still can't do\n");
  process.stdout.write("  ==========================================\n");
  process.stdout.write("  A repo-scoped GitHub token still merges a PR the instant an agent is\n");
  process.stdout.write("  told to, and it's the agent's to leak. Same agent, behind Grenz:\n\n");
  process.stdout.write("  WHAT THE AGENT TRIES                 VERDICT WHY\n");

  await act("read a repo (its real job)", "GET", "/u/github/repos/o/r");

  // In-scope for a PAT, held for a human here. The operator denies it.
  const merge = act("merge a PR (a scoped PAT just does)", "PUT", "/u/github/repos/o/r/pulls/1/merge");
  await decidePending((id) => {
    broker.deny(id, "you");
  });
  await merge;

  // The ONLY thing that revokes the agent — so the token_revoked below is
  // genuinely caused by this operator revoke, not a decoy tripwire side effect.
  revocations.revoke(AGENT, "operator cut it off", Date.now());
  process.stdout.write("  -- you revoke the agent — one command, no GitHub round-trip --\n");
  await act("read a repo", "GET", "/u/github/repos/o/r");

  process.stdout.write(
    "\n  A tightly-scoped token would have merged that PR and kept working. Behind\n" +
      "  Grenz the merge waited for your yes, the agent never held the real\n" +
      "  credential, and one `grenz revoke` cut it off without touching GitHub.\n" +
      "  No real credentials were used; nothing was left on disk.\n\n",
  );

  log.close();
  fake.stop(true);
  await rm(tmp, { recursive: true, force: true });
  return 0;
}
