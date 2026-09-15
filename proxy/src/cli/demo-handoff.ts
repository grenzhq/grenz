/**
 * `grenz demo-handoff` — the sub-agent problem, refused live in ~1 second.
 *
 * A swarm passes one task down a chain: lead -> triage -> fixer -> committer.
 * Every framework that ships "agent identity" authenticates all four of them
 * correctly. None of them constrains what one agent hands to the next, so the
 * agent at the end of the chain acts with the authority of the one at the top
 * and the merge lands with nobody asking a human.
 *
 * Grenz's answer is that authority can only narrow on the way down. Each hop
 * mints a strictly smaller sub-token, every request is evaluated as the
 * INTERSECTION of the live policy and every hop in the chain, and a descendant
 * that claims more than its parent held gains nothing by claiming it.
 *
 * Entirely in-process: the github upstream is a loopback stub, the vault holds
 * a dummy value, nothing is left on disk. The refusal is demonstrated on the
 * reader's own machine against a real policy, not asserted.
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

// The ROOT agent really is allowed to merge — that is the point. The refusal
// below is never "the policy forbids merging"; it is "this agent, at this depth,
// was not handed that." A demo where the root also lacked the power would prove
// nothing about delegation.
const POLICY = `
agent: ${LEAD}
on_behalf_of: demo@grenz.dev
grants:
  - tool: github
    allow: [repo:read, pr:read, pr:create, pr:merge]
`;

export async function runDemoHandoff(_args: ParsedArgs): Promise<number> {
  const compiled = compilePolicyYaml(POLICY);
  if (!compiled.ok) {
    process.stderr.write("grenz: demo policy failed to compile\n");
    return 1;
  }

  const fake = Bun.serve({ port: 0, fetch: () => new Response("{}", { status: 200 }) });
  const tmp = await mkdtemp(join(tmpdir(), "grenz-handoff-"));
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
    notifier: { approvalRequested: async () => {} },
    emit: () => {}, // the demo narrates itself; silence the proxy's own log lines
  });

  const now = Date.now();

  // The handoff. Each hop keeps less than the one above it: the lead may merge,
  // triage may not, and by the time the task reaches the committer all that is
  // left is opening a pull request.
  const { token: triageToken, delegation: triage } = await delegations.mint({
    parentAgentId: LEAD,
    actions: ["repo:read", "pr:read", "pr:create"],
    ttlMs: 900_000,
    note: "triage",
    now,
  });
  const { token: fixerToken, delegation: fixer } = await delegations.mint({
    parentAgentId: LEAD,
    parentDelegationId: triage.id,
    actions: ["repo:read", "pr:create"],
    ttlMs: 900_000,
    note: "fixer",
    now,
  });
  const { token: committerToken, delegation: committer } = await delegations.mint({
    parentAgentId: LEAD,
    parentDelegationId: fixer.id,
    actions: ["repo:read", "pr:create"],
    ttlMs: 900_000,
    note: "committer",
    now,
  });

  const act = async (who: string, what: string, token: string, method: string, path: string) => {
    const res = await handler(
      new Request(`http://grenz.local${path}`, { method, headers: { authorization: `Bearer ${token}` } }),
    );
    const dec = res.headers.get("x-grenz-decision") ?? "?";
    const reason = res.headers.get("x-grenz-reason") ?? "";
    process.stdout.write(`  ${who.padEnd(11)} ${what.padEnd(26)} ${dec.padEnd(6)} ${reason}\n`);
  };

  const out = (s: string) => process.stdout.write(s);

  out("\n  Grenz — the agent at the end of the chain cannot merge\n");
  out("  =====================================================\n");
  out("  One task, handed down a swarm. Every hop keeps strictly less:\n\n");
  out("    lead        repo:read  pr:read  pr:create  pr:merge\n");
  out("      -> triage   repo:read  pr:read  pr:create\n");
  out("        -> fixer    repo:read  pr:create\n");
  out("          -> committer  repo:read  pr:create\n\n");
  out("  WHO         DOES                       DECISION WHY\n");

  out("  -- the work itself: everyone reads, the committer opens the PR --\n");
  await act("lead", "read the repo", leadToken, "GET", "/u/github/repos/o/r");
  await act("triage", "read the pull request", triageToken, "GET", "/u/github/repos/o/r/pulls/7");
  await act("fixer", "read the repo", fixerToken, "GET", "/u/github/repos/o/r");
  await act("committer", "open a pull request", committerToken, "POST", "/u/github/repos/o/r/pulls");

  out("  -- the lead may merge. it was handed that, and it still holds it --\n");
  await act("lead", "merge the PR", leadToken, "PUT", "/u/github/repos/o/r/pulls/7/merge");

  out("  -- the incident: the committer, four hops down, merges its own fix --\n");
  await act("committer", "merge the PR", committerToken, "PUT", "/u/github/repos/o/r/pulls/7/merge");

  // The interesting half. A compromised sub-agent's obvious next move is to mint
  // itself a token that simply claims the power it was refused. Attenuation is an
  // intersection, so the ancestor that never held pr:merge still has to match —
  // and it cannot. Claiming more is not the same as being given more.
  const { token: forgedToken } = await delegations.mint({
    parentAgentId: LEAD,
    parentDelegationId: committer.id,
    actions: ["repo:read", "pr:create", "pr:merge"],
    ttlMs: 900_000,
    note: "committer's own sub-token, claiming pr:merge",
    now,
  });

  out("  -- so it mints itself a sub-token that CLAIMS pr:merge --\n");
  await act("its child", "merge the PR", forgedToken, "PUT", "/u/github/repos/o/r/pulls/7/merge");

  out(
    "\n  The root agent is allowed to merge — the policy says so, and the lead did it\n" +
      "  above. What the committer lacked was not permission in the policy but authority\n" +
      "  in the chain: nobody handed it down, and a request is evaluated as the live\n" +
      "  policy INTERSECTED with every hop it travelled. That is also why the last line\n" +
      "  fails. A sub-agent can write pr:merge on a token it mints, but its parent never\n" +
      "  held pr:merge, and an intersection cannot grow. Claiming is not being granted.\n" +
      "\n" +
      "  Without this, all four agents share one token. Then step three is a merged PR,\n" +
      "  and you find out after it deploys.\n" +
      "\n" +
      "  No real credentials were used; nothing was left on disk.\n\n",
  );

  log.close();
  fake.stop(true);
  await rm(tmp, { recursive: true, force: true });
  return 0;
}
