#!/usr/bin/env bun
/**
 * `grenz` CLI entrypoint.
 *
 * Commands: init | run | vault <set|list> | policy check | version | help.
 * All command handlers return an exit code; this wrapper turns thrown errors
 * into a clean non-zero exit without dumping a stack (which could reference
 * injected values).
 */
import { parseArgs, flagBool, type ParsedArgs } from "./cli/args.ts";
import { runInit } from "./cli/init.ts";
import { runRun } from "./cli/run.ts";
import { runVault } from "./cli/vault.ts";
import { runPolicy } from "./cli/policy.ts";
import { runApprovals, runApprove, runDeny, runStatus } from "./cli/approvals.ts";
import { runAdd, runTemplate } from "./cli/add.ts";
import { runStats } from "./cli/stats.ts";
import { runRisk } from "./cli/risk.ts";
import { runBlastRadius } from "./cli/blast-radius.ts";
import { runExplain } from "./cli/explain.ts";
import { runRevoke, runRestore, runRevocations } from "./cli/revoke.ts";
import { runRevocationsSign } from "./cli/revocation-sign.ts";
import { runRotate } from "./cli/rotate.ts";
import { runDecoy } from "./cli/decoy.ts";
import { runWrap } from "./cli/wrap.ts";
import { runProtect } from "./cli/protect.ts";
import { runConnect } from "./cli/connect.ts";
import { runScan } from "./cli/scan.ts";
import { runDemoAttack } from "./cli/demo-attack.ts";
import { runDemoCascade } from "./cli/demo-cascade.ts";
import { runDemoHandoff } from "./cli/demo-handoff.ts";
import { runDelegate, runDelegations } from "./cli/delegate.ts";
import { hookCommand } from "./cli/hook.ts";
import { runAgent } from "./cli/agent.ts";
import { runAgents } from "./cli/agents.ts";
import { runService } from "./cli/service.ts";
import { runGrant, runGrants } from "./cli/grant.ts";
import { runSuggest } from "./cli/suggest.ts";
import { runDoctor } from "./cli/doctor.ts";
import { runToken } from "./cli/token.ts";
import { runBreakGlass } from "./cli/break-glass.ts";

export const VERSION = "0.3.0";

const HELP = `grenz ${VERSION} — scoped, revocable permissions for AI agents

USAGE
  grenz <command> [options]

COMMANDS
  init                 Scaffold a Grenz home (identity, vault, config, policy)
  protect              One command: vault your token + safe defaults + how to wire your agent (--tool github [--strict])
  connect              Connect to the plane: prints a code, you approve it in the console, done
                       (--plane <url> for self-hosted, --telemetry, --force)
  connect <url>        Same, but with a policy URL and a token you already hold
                       (--public-key <b64>[,<b64>] to require signed bundles)
  scan                 Find plaintext credentials in agent config files an infostealer would harvest (exit 1 if any) [path…]
  demo-attack          See what a scoped token still can't do in ~1s (in-process; no real creds, nothing left on disk)
  demo-cascade         Watch one tripped decoy revoke a whole agent swarm in ~1s (in-process; no real creds)
  demo-handoff         Watch a sub-agent four hops down get refused the merge its lead could do (in-process)
  doctor               Preflight-check a Grenz home (offline; exit 1 on problems)
  run                  Start the proxy
  service <cmd>        Keep the proxy alive across reboots via launchd/systemd (print|install|uninstall|status)
  hook                 Gate a coding agent's Bash commands (Claude Code PreToolUse hook; reads stdin)
  wrap                 Advise how to put an MCP client behind Grenz (reads .mcp.json; --config <path>)
  vault set <key>      Store a credential (value read from stdin)
  vault list           List credential keys (names only)
  policy check         Validate + summarize the policy
  policy lint          Static checks: dead/shadowed patterns, broad grants
  policy diff <file>   Lint + replay a candidate policy against history
  policy test [file]   Assert (tool, action, target) -> decision via the engine
  policy shrinkwrap    Tighten allow lists to actions actually used (from the log)
  policy canary        Compare a running --canary candidate against live traffic
  policy keygen        Generate an Ed25519 policy-signing keypair (sign off-plane)
  policy sign <file>   Sign a policy into a versioned bundle (--key, --version
                       [--profile name=path,...] [--clear-profiles] [--force-version])
  suggest "<intent>"   Draft a candidate policy from plain English (LLM-assisted)
  add <tool>           Add a policy template (--template <name>)
  template list        List bundled policy templates
  approvals            List pending approvals
  approve <id>         Approve a pending request
  deny <id>            Deny a pending request
  revoke <agent>       Cut an agent off now (kill-switch; --reason "...")
  restore <agent>      Lift a revocation
  agent create <id>    Mint a first-class agent, live, with its own token (--policy <name>, --actions a,b, and/or --targets glob,glob to confine it)
  agents               List first-class agents (id, profile, scope, expiry)
  rotate <agent>       Issue a fresh GRENZ_TOKEN (rewrites grenz.yaml)
  revocations          List revoked agents (local + cached fleet set)
  revocations sign     Sign the revocation set into a versioned bundle (--key, --version [--from-local] [--expires-in])
  delegate <agent>     Mint an attenuated sub-token (--actions a,b [--targets glob,glob] [--ttl s] [--note])
  delegations          List live delegations
  grant <agent>        Temporarily widen an agent's own token (--actions a,b [--ttl s] [--reason "..."])
  grants               List active temporary grants
  token create <name>  Mint a named admin token (--role viewer|approver|admin)
  token list           List named admin tokens (console RBAC operators)
  token revoke <name>  Revoke a named admin token
  break-glass <agent>  Emergency unlock a denied action for approval (--action a,b --reason "..." [--ttl] [--quorum])
  break-glass          List active break-glass windows
  status               Show a live decision summary
  stats                Show anonymized aggregate decision counts (24h)
  risk                 Score agents by recent denial activity (SOC signal)
  blast-radius [agent] Static reachable-action exposure (leaked-token blast radius)
  explain <tool> <action> [target]  Why would this be allowed/denied right now? (--agent <id>)
  version              Print version
  help                 Show this help

COMMON OPTIONS
  --home <dir>         Grenz home directory (default: ./.grenz or $GRENZ_HOME)
  --port <n>           Override the listen port (run; also targets approvals/approve/deny)
  --host <addr>        Override the bind address (run; use 0.0.0.0 in containers)
  --force              Overwrite existing config + policy (init)

EXAMPLE
  grenz init
  printf %s "$GITHUB_TOKEN" | grenz vault set github_token
  grenz run
`;

/** Extension seam for the Grenz Enterprise build. The OSS binary ships this
 *  empty; the (separately-licensed) EE overlay registers its commands here —
 *  e.g. `EE_COMMANDS.login = runLogin` — so the dispatch below picks them up
 *  without the OSS tree carrying any enterprise code. See docs/enterprise.md. */
export const EE_COMMANDS: Record<string, (args: ParsedArgs) => Promise<number>> = {};

export type Invocation = "empty" | "help" | "version" | "dispatch";

/** Classify a top-level invocation. Recognizes help/version in the COMMAND
 *  position (`grenz --version`, `-v`, `--help`, `-h`) — which the raw
 *  `argv[0]` command switch cannot, since `argv[0]` is read before `parseArgs`
 *  — while preserving the post-command flag fallback (`grenz run --help`).
 *  Pure: no I/O. */
export function classifyInvocation(argv: readonly string[]): Invocation {
  const command = argv[0];
  const args = parseArgs(argv.slice(1));
  if (command === undefined) return "empty";
  if (command === "help" || command === "--help" || command === "-h" || flagBool(args, "help")) {
    return "help";
  }
  if (command === "version" || command === "--version" || command === "-v" || flagBool(args, "version")) {
    return "version";
  }
  return "dispatch";
}

async function main(): Promise<number> {
  const argv = Bun.argv.slice(2);
  switch (classifyInvocation(argv)) {
    case "empty":
      process.stdout.write(HELP);
      return 1;
    case "help":
      process.stdout.write(HELP);
      return 0;
    case "version":
      process.stdout.write(`grenz ${VERSION}\n`);
      return 0;
    case "dispatch":
      break;
  }
  const command = argv[0]!;
  const args = parseArgs(argv.slice(1));

  switch (command) {
    case "init":
      return runInit(args);
    case "protect":
      return runProtect(args);
    case "connect":
      return runConnect(args);
    case "scan":
      return runScan(args);
    case "demo-attack":
      return runDemoAttack(args);
    case "demo-cascade":
      return runDemoCascade(args);
    case "demo-handoff":
      return runDemoHandoff(args);
    case "doctor":
      return runDoctor(args);
    case "run":
      return runRun(args);
    case "service":
      return runService(args);
    case "wrap":
      return runWrap(args);
    case "vault":
      return runVault(args);
    case "policy":
      return runPolicy(args);
    case "suggest":
      return runSuggest(args);
    case "add":
      return runAdd(args);
    case "template":
      return runTemplate(args);
    case "approvals":
      return runApprovals(args);
    case "approve":
      return runApprove(args);
    case "deny":
      return runDeny(args);
    case "status":
      return runStatus(args);
    case "stats":
      return runStats(args);
    case "risk":
      return runRisk(args);
    case "blast-radius":
      return runBlastRadius(args);
    case "explain":
      return runExplain(args);
    case "revoke":
      return runRevoke(args);
    case "restore":
      return runRestore(args);
    case "agent":
      return runAgent(args);
    case "agents":
      return runAgents(args);
    case "rotate":
      return runRotate(args);
    case "decoy":
      return runDecoy(args);
    case "revocations":
      return args.positionals[0] === "sign" ? runRevocationsSign(args) : runRevocations(args);
    case "hook":
      return hookCommand(args);
    case "delegate":
      return runDelegate(args);
    case "delegations":
      return runDelegations(args);
    case "grant":
      return runGrant(args);
    case "grants":
      return runGrants(args);
    case "token":
      return runToken(args);
    case "break-glass":
      return runBreakGlass(args);
    default: {
      const ee = EE_COMMANDS[command];
      if (ee) return ee(args);
      // `grenz --home /x init` is a natural thing to type — the help lists
      // --home under COMMON OPTIONS, which reads as global — and answering it
      // with `unknown command "--home"` over sixty lines of banner leaves the
      // reader to work out the ordering rule themselves. Name the fix instead.
      if (command.startsWith("-")) {
        // Re-parse the FULL argv: `args` was parsed from argv.slice(1), so for
        // `--home /x init` its first positional is the option's own value.
        const intended = parseArgs(argv).positionals[0] ?? "<command>";
        process.stderr.write(
          `grenz: "${command}" is an option, not a command — options go after the command\n` +
            `  try: grenz ${intended} ${command} ...\n`,
        );
        return 1;
      }
      process.stderr.write(`grenz: unknown command "${command}"\n\n${HELP}`);
      return 1;
    }
  }
}

if (import.meta.main) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`grenz: ${message}\n`);
      process.exit(1);
    });
}
