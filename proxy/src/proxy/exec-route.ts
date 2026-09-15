/**
 * `POST /exec` — the pre-action gate for shell commands.
 *
 * Grenz's other surfaces intercept HTTP on the way to a credential. This one
 * intercepts nothing: `grenz hook` ASKS before Claude Code runs a `Bash` tool
 * call, and acts on the answer. There is no request to forward and no credential
 * to inject, which is why this route stops at the verdict.
 *
 * ## Why the decision lives here and not in the hook
 *
 * The hook is a subprocess spawned once per Bash call. Everything a decision
 * needs is in the running daemon: the loaded parser (a wasm load per call would
 * put ~22ms on every command), the budget counters, the request log's SQLite
 * handle (a second process opening it hits single-writer contention), and the
 * approval broker — a `require_approval` verdict has to block on the broker that
 * owns the pending set, which a subprocess cannot do at all.
 *
 * So `cli/hook.ts` is a thin client: it POSTs here over the same unix socket the
 * agent listener already serves, and translates the verdict. It never loads the
 * parser and never evaluates policy.
 *
 * ## Which gates run
 *
 * Enumerated deliberately, and tested. This route reuses the shared helpers
 * rather than re-deriving any decision:
 *
 *   auth -> decoy -> kill-switch -> wrong-listener -> adapter ->
 *   agent scope -> delegation fold -> policy select -> tripwire ->
 *   engine -> approval -> budget -> log
 *
 * The gates it does NOT run are the ones with no meaning without an upstream
 * request: upstream resolution, decoy upstream, DLP body scan, response cap,
 * egress pinning, the vault read, and forwarding. A shell command carries no
 * body toward a credentialed origin, so there is nothing for those to inspect.
 *
 * Everything here is additive: `/u/*` dispatch is untouched.
 */
import type { Parser } from "web-tree-sitter";
import type { CompiledPolicy } from "../policy/compile.ts";
import type { Decision, EngineResult, ReasonCode } from "../policy/types.ts";
import { evaluate, actionCost, approvalQuorum } from "../policy/evaluate.ts";
import { globMatch } from "../policy/glob.ts";
import { matchTripwire } from "../policy/tripwire.ts";
import { BASH_TOOL, mapBashCommand, isUndecidable, isUnsupported, type SyntaxNode } from "../adapters/bash.ts";
import type { LogEntry } from "../log/request-log.ts";
import type { Principal } from "./auth.ts";

/** What the hook sends. Anything else is refused. */
export interface ExecRequest {
  readonly command: string;
  /** Working directory the command would run in. Display only, never matched. */
  readonly cwd?: string;
}

/** What the hook receives. */
export interface ExecVerdict {
  readonly decision: Decision;
  readonly reason: ReasonCode;
  /** The action that decided it — `exec:curl`, or `-` when nothing was mapped. */
  readonly action: string;
  /** Log-safe display label for the command. Never a matching input. */
  readonly target: string;
  /** Operator-authored remediation hint from the matched rule, when present. */
  readonly message?: string;
}

/** Parse and validate the body without pulling Zod into the hot path. */
export function parseExecRequest(raw: unknown): ExecRequest | { error: string } {
  if (raw === null || typeof raw !== "object") return { error: "body must be a JSON object" };
  const cmd = (raw as { command?: unknown }).command;
  if (typeof cmd !== "string") return { error: "missing string `command`" };
  // A bounded input: an unbounded command string is a parser DoS, and nothing
  // legitimate approaches this.
  if (cmd.length > MAX_COMMAND_BYTES) return { error: "command too long" };
  const cwd = (raw as { cwd?: unknown }).cwd;
  return { command: cmd, ...(typeof cwd === "string" ? { cwd } : {}) };
}

export const MAX_COMMAND_BYTES = 64 * 1024;

/**
 * What `unresolved_target` means, for the agent that reads the refusal. The
 * hook feeds this back to the model, so it says what to do, not just what
 * happened. An operator's own rule `message` takes precedence when present.
 */
export const UNRESOLVED_TARGET_HINT =
  "an argument contains a shell variable or expansion Grenz cannot resolve before the command " +
  "runs. Write the literal value instead. An operator can set `on_unresolved: approve` on the " +
  "allow rule to route such commands to a human";

/**
 * Everything `handleExec` needs from the server, passed explicitly so the route
 * is testable without standing up a full proxy.
 */
export interface ExecDeps {
  readonly parser: Parser | null;
  readonly policy: CompiledPolicy;
  readonly principal: Principal;
  readonly sessionKey: string;
  readonly now: number;
  /** Cost already spent in the budget window, for this agent. */
  readonly spent: number;
  /** Agent ceiling for the window, or null when uncapped. */
  readonly ceiling: { limit: number | null; override: boolean };
  revoke?(target: string, reason: string, ts: number): void;
  notifyTripwire?(actor: string, action: string, target: string, note: string | null): void;
}

/** The engine verdict for a whole command line: deny wins, then approval. */
export function combineExec(
  policy: CompiledPolicy,
  actions: readonly string[],
  targets: readonly string[],
  unresolved: readonly boolean[] = [],
): { result: EngineResult; action: string } {
  let approval: { result: EngineResult; action: string } | null = null;
  for (let i = 0; i < actions.length; i++) {
    const action = actions[i]!;
    // Each action is evaluated against ITS OWN target, and its OWN resolution
    // state. Never the display label, and never a collapsed flag:
    // `git add . && curl $URL` must not let the curl ride the git's grant, and
    // must not let the git's certainty cover the curl's unresolved argument.
    const result = evaluate(policy, {
      tool: BASH_TOOL,
      action,
      target: targets[i]!,
      unresolved: unresolved[i] === true,
    });
    if (result.decision === "deny") return { result, action };
    if (result.decision === "require_approval" && !approval) approval = { result, action };
  }
  if (approval) return approval;
  const action = actions.length === 1 ? actions[0]! : `batch:${actions.length}`;
  return {
    result: { decision: "allow", reason: "explicit_allow", matched: "allow", pattern: null },
    action,
  };
}

/** Total billable cost of a command line — a list of N commands bills all N. */
export function execCost(policy: CompiledPolicy, actions: readonly string[]): number {
  let total = 0;
  for (const a of actions) total += actionCost(policy, a);
  return total;
}

/** The strictest quorum across every action in the line. */
export function execQuorum(policy: CompiledPolicy, actions: readonly string[]): number {
  let q = 1;
  for (const a of actions) q = Math.max(q, approvalQuorum(policy, a));
  return q;
}

export interface ExecDecision {
  readonly verdict: ExecVerdict;
  /** The (action, target) pairs, for the log and for an approval prompt. */
  readonly pairs: readonly { action: string; target: string }[];
  /** Billable cost if this is allowed. */
  readonly cost: number;
  /** Set when the verdict is require_approval and a human must be asked. */
  readonly quorum: number;
}

/**
 * Decide a command line, up to (but not including) the approval block and the
 * budget check — both need IO the caller owns. Pure with respect to the parser.
 *
 * Returns a settled deny, or a decision the caller carries through approval and
 * budget. Every failure path here is a DENY with a structured reason.
 */
export function decideExec(command: string, deps: ExecDeps): ExecDecision {
  const settled = (reason: ReasonCode, target: string, message?: string): ExecDecision => ({
    verdict: { decision: "deny", reason, action: "-", target, ...(message ? { message } : {}) },
    pairs: [],
    cost: 0,
    quorum: 1,
  });

  // The parser failing to load is not a reason to guess. Deny.
  if (deps.parser === null) {
    return settled("exec_parse_failed", "-", "the command guard's parser is not loaded");
  }

  let root: SyntaxNode;
  try {
    const tree = deps.parser.parse(command);
    if (tree === null) return settled("exec_parse_failed", "-", "command did not parse");
    root = tree.rootNode as unknown as SyntaxNode;
  } catch {
    return settled("exec_parse_failed", "-", "command did not parse");
  }

  const mapping = mapBashCommand(root, command);
  if (isUnsupported(mapping)) {
    return settled("exec_parse_failed", "-", mapping.unsupported);
  }
  if (isUndecidable(mapping)) {
    // The HARD refusals: nothing could be named, so there is no action to hand
    // the engine and no policy can allow them. An argv-only unknown (`curl
    // $URL`) is NOT here — it is decidable as an action, and reaches the engine
    // below carrying `mapping.unresolved`.
    return settled("exec_undecidable", "-", `${mapping.undecidable}: ${mapping.detail}`);
  }

  const pairs = mapping.actions.map((action, i) => ({ action, target: mapping.targets[i]! }));

  // --- Agent scope --------------------------------------------------------
  const { principal } = deps;
  if (principal.agentActions.length > 0) {
    const beyond = mapping.actions.find(
      (a) => !principal.agentActions.some((p) => globMatch(p, a)),
    );
    if (beyond !== undefined) return settled("agent_action_scope", mapping.target);
  }
  if (principal.agentTargets.length > 0) {
    // Unprovable is not "within scope". A confinement gate asks the agent to
    // demonstrate it stays inside a boundary, and `curl $URL` cannot — even
    // though `globMatch("curl *", "curl $URL")` is true of the STRING. Same
    // rule as the engine's, applied to the same question one gate earlier.
    const beyond = mapping.targets.find(
      (t, i) => mapping.unresolved[i] === true || !principal.agentTargets.some((p) => globMatch(p, t)),
    );
    if (beyond !== undefined) return settled("agent_target_scope", mapping.target);
  }

  // --- Delegation fold ----------------------------------------------------
  // live_policy(root) ∩ grant₁ ∩ … ∩ grantₙ, same intersection rule as /u/*:
  // every hop must match every action, and every hop that constrains targets
  // must match every target. First miss denies the whole line.
  if (principal.kind === "delegation") {
    const beyond = mapping.actions.find(
      (a) => !principal.actionsChain.every((hop) => hop.some((p) => globMatch(p, a))),
    );
    if (beyond !== undefined) return settled("delegation_scope", mapping.target);
    const blocked = mapping.targets.find(
      (t, i) =>
        principal.targetsChain.some(
          (hop) => hop.length > 0 && (mapping.unresolved[i] === true || !hop.some((p) => globMatch(p, t))),
        ),
    );
    if (blocked !== undefined) return settled("delegation_target_scope", mapping.target);
  }

  // --- Tripwire -----------------------------------------------------------
  // Checked over EVERY command in the line, before the engine, so a would-deny
  // still trips it and nothing rides past inside a batch.
  for (const { action, target } of pairs) {
    const wire = matchTripwire(deps.policy.tripwires, action, target);
    if (wire) {
      const revokeTarget = wire.onTrip === "leaf" ? deps.sessionKey : principal.agentId;
      const via = revokeTarget !== deps.sessionKey ? ` (via ${deps.sessionKey})` : "";
      deps.revoke?.(
        revokeTarget,
        `tripwire: ${action}${wire.note ? ` — ${wire.note}` : ""}${via}`,
        deps.now,
      );
      deps.notifyTripwire?.(deps.sessionKey, action, target, wire.note ?? null);
      return settled("tripwire", target, wire.note ?? undefined);
    }
  }

  // --- Engine -------------------------------------------------------------
  const { result, action } = combineExec(
    deps.policy,
    mapping.actions,
    mapping.targets,
    mapping.unresolved,
  );
  // The reason code alone reads as a bug to the agent that receives it. Say what
  // the code means and what to do, since the hook feeds this text back to the
  // model. An operator-authored rule message still wins.
  const message =
    result.message ?? (result.reason === "unresolved_target" ? UNRESOLVED_TARGET_HINT : undefined);
  return {
    verdict: {
      decision: result.decision,
      reason: result.reason,
      action,
      target: mapping.target,
      ...(message ? { message } : {}),
    },
    pairs,
    cost: execCost(deps.policy, mapping.actions),
    quorum: execQuorum(deps.policy, mapping.actions),
  };
}

/** The log row for an exec decision. `upstream`/`tool` are both `bash`. */
export function execLogEntry(
  base: { ts: number; agentId: string; delegationId?: string | null },
  verdict: ExecVerdict,
  allowedCost: number,
): LogEntry {
  return {
    ts: base.ts,
    agentId: base.agentId,
    upstream: BASH_TOOL,
    tool: BASH_TOOL,
    action: verdict.action,
    method: "exec",
    target: verdict.target,
    decision: verdict.decision,
    reason: verdict.reason,
    // Nothing is forwarded on this route: Grenz decides, the agent's own runtime
    // performs. `forwarded` stays false so the column keeps meaning what it means
    // everywhere else — "Grenz sent this upstream".
    forwarded: false,
    status: null,
    count: allowedCost,
    ...(base.delegationId !== undefined ? { delegationId: base.delegationId } : {}),
  };
}
