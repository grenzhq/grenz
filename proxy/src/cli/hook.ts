/**
 * `grenz hook` — a Claude Code `PreToolUse` hook that gates the agent's `Bash`
 * commands through Grenz's policy engine.
 *
 * This process is DELIBERATELY THIN. It reads the hook payload, asks the running
 * proxy, and translates the answer. It does not load the parser, does not
 * evaluate policy, and does not open the request log. All of that lives in the
 * daemon (`proxy/exec-route.ts`), because:
 *
 *   - the tree-sitter wasm costs ~22ms to load, and this process is spawned once
 *     per Bash call
 *   - the budget counters and the log's SQLite handle live in the daemon; a
 *     second process opening the same database hits single-writer contention
 *   - a `require_approval` verdict has to block on the approval broker, which
 *     only the daemon owns
 *
 * ## Composition with Claude Code's own permissions
 *
 * A Grenz ALLOW is not an instruction to run the command — it is the absence of
 * an objection. The hook exits 0 and emits no `permissionDecision`, so Claude
 * Code's normal permission flow still applies. Emitting `"allow"` would BYPASS
 * the user's own allow-list and prompts, making Grenz a way to WIDEN permissions.
 * Grenz only ever narrows.
 *
 * ## Denying, twice over
 *
 * Claude Code has a known bug (#18312) where a tool already on the allow-list
 * ignores the hook's `permissionDecision`. Relying on the JSON alone would fail
 * open for exactly the users who configured `Bash` as always-allowed. So a deny
 * is expressed BOTH ways: the JSON decision on stdout AND exit code 2, which
 * blocks unconditionally and feeds stderr back to the model.
 *
 * ## Fail closed
 *
 * Daemon not running, socket missing, no token, timeout, malformed reply,
 * non-200 status, or a 200 whose body is not an explicit allow — every one of
 * them denies. There is no local fallback evaluation and no fallback to allow.
 */
import { loadConfig, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { resolveSocketPath } from "../config/socket-path.ts";
import { homeFlag, flagString, type ParsedArgs } from "./args.ts";

/** Claude Code's PreToolUse payload. Only the fields the guard needs. */
interface HookPayload {
  readonly hook_event_name?: unknown;
  readonly tool_name?: unknown;
  readonly tool_input?: unknown;
  readonly cwd?: unknown;
}

/** The tool this hook guards. Anything else passes through untouched. */
const GUARDED_TOOL = "Bash";

/** Wall-clock floor for the ask, independent of the approval TTL. */
const MIN_TIMEOUT_MS = 5_000;
/**
 * Absolute ceiling. Claude Code's own per-hook timeout defaults to 600s and a
 * hook that is still running when it fires does NOT block the call — the tool
 * proceeds through the normal permission flow. So this process must always
 * answer before that, or a slow approval would become a fail-open. 570s leaves
 * margin for process spawn and the JSON round-trip.
 */
const MAX_TIMEOUT_MS = 570_000;
/** Claude Code's default; documented so the cap above has a name to be checked against. */
export const CLAUDE_CODE_HOOK_TIMEOUT_MS = 600_000;

/** How long the hook waits on the daemon for an approval TTL of `ttlSeconds`. */
export function hookTimeoutMs(ttlSeconds: number): number {
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, ttlSeconds * 1000 + 10_000));
}

export interface HookOutcome {
  /** Process exit code: 0 to let the tool proceed, 2 to block it. */
  readonly code: number;
  /** JSON for stdout, or null to stay silent. */
  readonly stdout: string | null;
  /** Reason for stderr — what Claude Code feeds back to the model on exit 2. */
  readonly stderr: string | null;
}

/** A pass-through: Grenz has no objection, normal permission flow continues. */
export function proceed(): HookOutcome {
  return { code: 0, stdout: null, stderr: null };
}

/**
 * A block, expressed twice: the documented JSON decision, and exit 2 for the
 * allow-list bug that ignores it.
 */
export function block(reason: string): HookOutcome {
  return {
    code: 2,
    // Both spellings of the explanation are emitted: Anthropic's own hook
    // examples carry `systemMessage`, the PreToolUse reference carries
    // `permissionDecisionReason`. Sending both costs nothing and means the
    // human-readable reason survives either reading.
    stdout: JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason,
      },
      systemMessage: reason,
    }),
    // On exit 2 this is what Claude Code feeds back to the model, so it is
    // plain prose rather than JSON.
    stderr: reason,
  };
}

/** Read all of stdin. Returns null if nothing arrives. */
async function readStdin(): Promise<string | null> {
  try {
    const text = await Bun.stdin.text();
    return text.length === 0 ? null : text;
  } catch {
    return null;
  }
}

/** Extract the command string, or a reason it could not be found. */
export function commandFrom(payload: HookPayload): { command: string } | { skip: true } | { error: string } {
  // The absent case and the different-tool case are NOT the same, and conflating
  // them fails open. If the payload carries no readable tool name at all — a
  // renamed field, a schema change, a truncated write — then this hook cannot
  // tell a Bash call from anything else, and the one thing it must not do is
  // wave it through. An absent protective input denies; only a positively
  // identified OTHER tool skips.
  const name = payload.tool_name;
  if (typeof name !== "string" || name.length === 0) {
    return { error: "Grenz hook could not read `tool_name` from the hook payload" };
  }
  if (name !== GUARDED_TOOL) return { skip: true };

  const input = payload.tool_input;
  if (input === null || typeof input !== "object") {
    return { error: "Bash tool call had no tool_input object" };
  }
  const command = (input as { command?: unknown }).command;
  if (typeof command !== "string" || command.length === 0) {
    // A Bash call whose command we cannot read is exactly the case that must not
    // pass: absent protective input denies, it does not default to unconstrained.
    return { error: "Bash tool_input had no readable `command` string" };
  }
  return { command };
}

interface Endpoint {
  readonly url: string;
  readonly unix?: string;
  readonly timeoutMs: number;
}

/** Resolve where the daemon listens, or the reason we cannot tell. */
async function resolveEndpoint(args: ParsedArgs): Promise<Endpoint | { error: string }> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);
  let config;
  try {
    config = await loadConfig(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      return { error: `Grenz config could not be loaded (${err.message})` };
    }
    throw err;
  }

  // The ask can legitimately take as long as an approval: a require_approval
  // command blocks on a human. Shorter than the TTL and every approval-gated
  // command would auto-deny before anyone could answer. The daemon still bounds
  // it — an approval that expires resolves to DENY server-side.
  const timeoutMs = hookTimeoutMs(config.approvals.ttl_seconds);

  if (config.listen.socket !== undefined) {
    const resolved = resolveSocketPath(config.listen.socket, paths.home);
    if (!resolved.ok) return { error: resolved.error };
    // The host in the URL is ignored for a unix transport but must still parse.
    return { url: "http://localhost/exec", unix: resolved.path, timeoutMs };
  }

  const host = config.listen.host === "0.0.0.0" ? "127.0.0.1" : config.listen.host;
  const portOverride = flagString(args, "port");
  const port =
    portOverride !== undefined && Number.isInteger(Number(portOverride))
      ? Number(portOverride)
      : config.listen.port;
  return { url: `http://${host}:${port}/exec`, timeoutMs };
}

/** Error codes meaning nothing was listening — the proxy is not running. */
const NOT_LISTENING: ReadonlySet<string> = new Set([
  "ConnectionRefused",
  "ECONNREFUSED",
  "FailedToOpenSocket",
  "ENOENT",
]);

/**
 * Why the ask failed, in words the agent — and the human reading over its
 * shoulder — can act on. Every branch is still a deny.
 *
 * The old message said "start the proxy" for all of them, which sent people to
 * restart a proxy that was running fine while an approval sat unanswered.
 */
export function describeAskFailure(err: unknown, timeoutMs: number): string {
  const e = (err ?? {}) as { name?: unknown; code?: unknown };
  if (e.name === "TimeoutError") {
    return (
      `Grenz did not answer within ${Math.round(timeoutMs / 1000)}s, so the command was blocked. ` +
      "A command that needs no approval is answered in milliseconds, so this was most likely an " +
      "approval nobody decided in time — see `grenz approvals`."
    );
  }
  const code = typeof e.code === "string" ? e.code : null;
  if (code !== null && NOT_LISTENING.has(code)) {
    return (
      "Grenz is not reachable — the command was blocked because it could not be checked. " +
      "Start the proxy with `grenz run` (the guard needs `exec_guard: true` in grenz.yaml). " +
      "The agent cannot start it for you: with the proxy down, that command is blocked too."
    );
  }
  return (
    `The connection to Grenz closed before it answered${code ? ` (${code})` : ""}, so the command ` +
    "was blocked. Usually an approval waited longer than the proxy holds a request — see " +
    "`grenz approvals` — or the proxy stopped mid-request."
  );
}

/** The daemon's answer, already reduced to a decision. */
async function ask(
  endpoint: Endpoint,
  token: string,
  command: string,
  cwd: string | undefined,
): Promise<{ allow: true } | { deny: string }> {
  let res: Response;
  try {
    res = await fetch(endpoint.url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-grenz-token": token },
      body: JSON.stringify({ command, ...(cwd !== undefined ? { cwd } : {}) }),
      signal: AbortSignal.timeout(endpoint.timeoutMs),
      ...(endpoint.unix !== undefined ? { unix: endpoint.unix } : {}),
    } as RequestInit);
  } catch (err) {
    return { deny: describeAskFailure(err, endpoint.timeoutMs) };
  }

  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  const reason =
    body !== null && typeof body === "object" && typeof (body as { reason?: unknown }).reason === "string"
      ? (body as { reason: string }).reason
      : `http_${res.status}`;
  const hint =
    body !== null && typeof body === "object" && typeof (body as { hint?: unknown }).hint === "string"
      ? (body as { hint: string }).hint
      : null;
  const message =
    body !== null && typeof body === "object" && typeof (body as { message?: unknown }).message === "string"
      ? (body as { message: string }).message
      : null;

  // ONLY an explicit 200 + decision:"allow" proceeds. A 200 with any other body,
  // any other status, or an unreadable reply all deny.
  const decision =
    body !== null && typeof body === "object" ? (body as { decision?: unknown }).decision : undefined;
  if (res.status === 200 && decision === "allow") return { allow: true };

  const note = hint ?? message;
  return { deny: `Grenz denied this command (${reason})${note ? ` — ${note}` : ""}` };
}

/** Run the hook. Returns the outcome; the caller writes the streams and exits. */
export async function runHook(args: ParsedArgs): Promise<HookOutcome> {
  const raw = await readStdin();
  if (raw === null) {
    return block("Grenz hook received no input on stdin");
  }

  let payload: HookPayload;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object") {
      return block("Grenz hook input was not a JSON object");
    }
    payload = parsed as HookPayload;
  } catch {
    return block("Grenz hook input was not valid JSON");
  }

  const extracted = commandFrom(payload);
  if ("skip" in extracted) return proceed();
  if ("error" in extracted) return block(extracted.error);

  const token = process.env["GRENZ_TOKEN"];
  if (token === undefined || token.length === 0) {
    return block("GRENZ_TOKEN is not set — the command could not be checked");
  }

  const endpoint = await resolveEndpoint(args);
  if ("error" in endpoint) return block(`Grenz could not be reached: ${endpoint.error}`);

  const cwd = typeof payload.cwd === "string" ? payload.cwd : undefined;
  const verdict = await ask(endpoint, token, extracted.command, cwd);
  if ("allow" in verdict) return proceed();
  return block(verdict.deny);
}

/** CLI entry point. */
export async function hookCommand(args: ParsedArgs): Promise<number> {
  let outcome: HookOutcome;
  try {
    outcome = await runHook(args);
  } catch (err) {
    // An unexpected throw is still a deny. Nothing here is allowed to fail open.
    outcome = block(`Grenz hook failed: ${(err as Error).message}`);
  }
  if (outcome.stdout !== null) process.stdout.write(outcome.stdout + "\n");
  if (outcome.stderr !== null) process.stderr.write(outcome.stderr + "\n");
  return outcome.code;
}
