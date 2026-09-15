/**
 * The Grenz request pipeline.
 *
 * Every request flows: route -> authenticate -> resolve upstream -> map to
 * action(s) -> evaluate policy -> budget -> enforce (forward | deny). Every
 * branch fails closed (DENY) and records exactly one log entry. A real
 * credential is fetched from the vault only on the ALLOW path, only to be
 * injected on the outbound request, and never appears on the agent's response.
 */
import { headerSafe } from "../util/header.ts";
import type { GrenzConfig, UpstreamConfig, AgentConfig } from "../config/schema.ts";
import type { AgentStore } from "../agents/store.ts";
import type { Mutex } from "../util/mutex.ts";
import type { CompiledPolicy } from "../policy/compile.ts";
import type { Decision, EngineResult, ReasonCode } from "../policy/types.ts";
import { evaluate, withinUpstreamBudget, withinDelegationBudget, agentCeiling, agentRequiresApproval, actionCost, approvalQuorum } from "../policy/evaluate.ts";
import { withinSchedule } from "../policy/schedule.ts";
import { firstUseInScope } from "../policy/first-use.ts";
import { evaluateFlowsBatch, maxWithinMs } from "../flow/evaluate.ts";
import type { FlowFactStore } from "../flow/facts.ts";
import {
  evaluatePinBatch,
  pinUnitsFor,
  maxWithinMs as maxPinWithinMs,
  type ActionTarget,
} from "../pin/evaluate.ts";
import type { PinStore } from "../pin/store.ts";
import type { CanaryStore } from "../canary/store.ts";
import type { TokenStore } from "../admin/token-store.ts";
import type { PolicyDistributionState } from "../distribution/types.ts";
import type { BreakGlassStore } from "../breakglass/store.ts";
import { matchTripwire } from "../policy/tripwire.ts";
import { adapterFor } from "../adapters/index.ts";
import { isUnsupported, type AdapterRequest } from "../adapters/types.ts";
import { resolvePrincipal, extractToken, type Principal } from "./auth.ts";
import {
  decideExec,
  execLogEntry,
  parseExecRequest,
  MAX_COMMAND_BYTES,
  type ExecVerdict,
} from "./exec-route.ts";
import { BASH_TOOL } from "../adapters/bash.ts";
import { loadBashParser, bashParserSync } from "../exec/parser.ts";
import { resolveResponseLimit, type ResolvedResponseLimit } from "../response/limit.ts";
import { globMatch } from "../policy/glob.ts";
import { forward } from "./forward.ts";
import { resolveUpstreamUrl } from "./egress.ts";
import { handleConsole } from "./console.ts";
import { scanBytes, findingLabel } from "../dlp/scan.ts";
import type { CredentialStore } from "../vault/store.ts";
import { VaultError } from "../vault/store.ts";
import { RequestLog, type LogEntry } from "../log/request-log.ts";
import type { ApprovalBroker, ApprovalInput } from "../approvals/broker.ts";
import type { ApprovalMemory } from "../approvals/memory.ts";
import type { Notifier } from "../notify/notifier.ts";
import type { RevocationStore } from "../revoke/store.ts";
import type { FleetRevocationStore } from "../revocation/store.ts";
import type { RevocationDistributionState } from "../revocation/types.ts";
import { DelegationStore, delegateRequestSchema, DEFAULT_TTL_SECONDS, MAX_DEPTH } from "../delegate/store.ts";
import { scoreRisk } from "../risk/score.ts";
import { GrantStore } from "../grant/store.ts";
import { PolicyStore } from "../policy/store.ts";
import type { PolicyHistoryStore } from "../policy/history-store.ts";

const BUDGET_WINDOW_MS = 60 * 60 * 1000;
const AGENT_UNKNOWN = "-";

export interface ServerDeps {
  readonly config: GrenzConfig;
  /** Live agent set for console-minted agents. When present, the handler reads
   *  agents from here (initialized from config.agents) so a mint takes effect
   *  without a restart. Absent = static config.agents only. */
  readonly agentStore?: AgentStore;
  readonly policy: CompiledPolicy;
  /** Hot-reload: when present, the live policy is read from here per request,
   *  so `policy` above is only the initial value. */
  readonly policyStore?: PolicyStore;
  /** Policy version history — captured on a console policy edit (rollback). */
  readonly policyHistory?: PolicyHistoryStore;
  /** Path to the local policy.yaml — the source the console editor reads/writes.
   *  Editing is refused when a remote `policy_source` is configured. */
  readonly policyPath?: string;
  /** Path to the local grenz.yaml — the file a console agent-mint appends to.
   *  Present (with `agentStore` + `configWriteLock`) enables `POST /console/agents`. */
  readonly configPath?: string;
  /** Serializes grenz.yaml rewrites (console mints) against each other. */
  readonly configWriteLock?: Mutex;
  readonly vault: CredentialStore;
  readonly log: RequestLog;
  /** Gate 2: approval broker. When present, `require_approval` blocks on it. */
  readonly broker?: ApprovalBroker;
  /** Gate 2: how pending approvals are pushed to a human (Slack, …). */
  readonly notifier?: Notifier;
  /** Approval memory: a recent human approve/deny for the exact (agent, tool,
   *  action, target) short-circuits an identical re-prompt. Off when absent. */
  readonly approvalMemory?: ApprovalMemory;
  /** Gate 2: admin token gating the loopback console/admin API. */
  readonly adminToken?: string;
  /** Named admin tokens for console RBAC. When absent, only the bootstrap admin
   *  token works. */
  readonly tokenStore?: TokenStore;
  /** Live signed-policy-distribution state for /metrics. Absent = local policy. */
  readonly policyDistribution?: PolicyDistributionState;
  /** Kill-switch: revoked agents are denied at the door. When absent, none are. */
  readonly revocations?: RevocationStore;
  /** Fleet kill-set: signed, verified, cached. Unioned with `revocations` at the
   *  gate — consulted, never merged into the local store. When absent, off. */
  readonly fleetRevocations?: FleetRevocationStore;
  /** Live fleet-revocation state for /metrics and the stale-closed gate.
   *  Absent = no fleet channel. */
  readonly revocationDistribution?: RevocationDistributionState;
  /** Delegation: attenuated sub-tokens for spawned sub-agents. When absent, off. */
  readonly delegations?: DelegationStore;
  /** JIT grants: temporary widenings of an agent's own token. When absent, off. */
  readonly grants?: GrantStore;
  /** Break-glass windows: a loud, time-boxed admin unlock that turns a denied
   *  action into a fresh approval. When absent, no window ever applies. */
  readonly breakGlass?: BreakGlassStore;
  /** Taint-flow facts: ephemeral per-token-holder source-action memory. When
   *  absent, flow rules are inert. */
  readonly flowFacts?: FlowFactStore;
  /** Session pin facts: ephemeral per-token-holder target-unit memory. When
   *  absent, pin rules are inert. */
  readonly pinFacts?: PinStore;
  /** Shadow-policy canary: a candidate policy evaluated (pure engine) alongside
   *  the live one. Never affects the live decision; only observed. Inert unless
   *  BOTH `canaryPolicy` and `canaryStore` are present. */
  readonly canaryPolicy?: CompiledPolicy;
  readonly canaryStore?: CanaryStore;
  /** Shadow mode: forward policy would-denies/would-approvals, logging them as
   *  observations instead of enforcing. Off (enforce) when absent. */
  readonly shadow?: boolean;
  /** Socket mode: false marks this handler as the ADMIN (TCP) listener, which
   *  serves the console/metrics/healthz plane but refuses agent routes. Defaults
   *  to true — the socket listener, and every TCP-only deployment, are unchanged. */
  readonly agentRoutesEnabled?: boolean;
  /** Bash command guard: enables `POST /exec`. Off when absent — the route
   *  answers 404 and no parser is loaded. */
  readonly execGuard?: boolean;
  /** Injectable clock (budget window + log timestamps). Defaults to wall clock. */
  readonly now?: () => number;
  /** Emit an operational one-liner to stderr. Defaults to console.error. */
  readonly emit?: (line: string) => void;
}

const STATUS_BY_REASON: Partial<Record<ReasonCode, number>> = {
  invalid_token: 401,
  agent_token_expired: 401, // masked on the wire as invalid_token
  delegation_root_missing: 401, // masked on the wire as invalid_token
  unsupported_request: 400,
  budget_exceeded: 429,
  upstream_budget_exceeded: 429,
  agent_budget_exceeded: 429,
  delegation_budget_exceeded: 429,
  approval_capacity: 429,
  approval_abandoned: 499, // "client closed request" (nginx); within Fetch 200-599
  flow_denied: 403,
  tripwire: 403,
  decoy_token: 401,
  decoy_upstream: 403,
  wrong_listener: 403,
  exec_undecidable: 403,
  exec_parse_failed: 400,
  // The action was decidable, the target was not, and no unscoped rule claimed
  // it. A deny like any other from the agent's side.
  unresolved_target: 403,
  // Never reaches denyStatus in practice — the decision is require_approval, so
  // the approval path owns the response. Mapped anyway so a future caller that
  // denies on it does not silently fall through to the 403 default.
  unresolved_approval: 403,
  pin_violation: 403,
  credential_missing: 502,
  vault_error: 502,
  upstream_error: 502,
  internal_error: 500,
  agent_policy_unresolved: 403,
  response_too_large: 413,
};

function denyStatus(reason: ReasonCode): number {
  return STATUS_BY_REASON[reason] ?? 403;
}

interface RouteMatch {
  readonly upstreamName: string;
  readonly path: string;
  readonly query: string;
}

/** Parse `/u/<name>` or `/u/<name>/<rest...>`. */
function matchUpstreamRoute(url: URL): RouteMatch | null {
  const m = /^\/u\/([^/]+)(\/.*)?$/.exec(url.pathname);
  if (!m || !m[1]) return null;
  return {
    upstreamName: decodeURIComponent(m[1]),
    path: m[2] ?? "/",
    query: url.search.startsWith("?") ? url.search.slice(1) : "",
  };
}

/**
 * Combine a batch of per-action results: deny wins, then approval, then allow.
 *
 * Each action is evaluated against ITS OWN target (`targets[i]`), never against
 * the request's collapsed display label — a batch must not launder a member past
 * a target-scoped rule.
 */
function combine(
  policy: CompiledPolicy,
  tool: string,
  actions: readonly string[],
  targets: readonly string[],
): { result: EngineResult; action: string } {
  let approval: { result: EngineResult; action: string } | null = null;
  for (let i = 0; i < actions.length; i++) {
    const action = actions[i]!;
    const result = evaluate(policy, { tool, action, target: targets[i]! });
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

export function createHandler(deps: ServerDeps): (req: Request) => Promise<Response> {
  const now = deps.now ?? (() => Date.now());
  const emit = deps.emit ?? ((line: string) => console.error(line));
  const upstreams = deps.config.upstreams;
  const getPolicy = (): CompiledPolicy => deps.policyStore?.current ?? deps.policy;
  /** The live agent set. When an AgentStore is present (console minting enabled),
   *  a console-minted agent authenticates immediately — otherwise the static
   *  config.agents, unchanged. */
  const liveAgents = (): readonly AgentConfig[] => deps.agentStore?.current ?? deps.config.agents;
  /** Agent ids already reported on the wrong listener — the notification fires
   *  once per agent per process, while every occurrence is still logged. */
  const wrongListenerNotified = new Set<string>();

  // Embed guard (fail closed): a profile only takes effect through the store's
  // policyFor. If an embedder wires profile-bearing agents OR configured
  // delegations but no policyStore, those profiles would be silently ignored —
  // refuse to construct instead. Runs once at construction, never per request.
  {
    const agentsWithProfile = liveAgents().some((a) => a.policy !== undefined);
    const delegationsWithProfile =
      deps.delegations?.list(now()).some((d) => d.policyProfile !== undefined) ?? false;
    if ((agentsWithProfile || delegationsWithProfile) && !deps.policyStore) {
      throw new Error(
        "createHandler: agents or delegations declare `policy` profiles but no policyStore was provided — " +
          "per-agent policy cannot be enforced without it (fail closed)",
      );
    }
  }

  function record(entry: LogEntry): void {
    try {
      deps.log.record(entry);
    } catch {
      // A logging failure must never break request handling or mask a performed
      // action's response. Surface it operationally and continue.
      emit(`[log-error] failed to persist ${entry.decision} ${entry.upstream}:${entry.action}`);
    }
    const flow = entry.forwarded ? `-> ${entry.status ?? "?"}` : "blocked";
    const label = entry.shadow ? `[shadow] would-${entry.decision}` : `[${entry.decision}]`;
    emit(`${label} ${entry.agentId} ${entry.upstream}:${entry.action} ${flow} (${entry.reason})`);
  }

  function deny(
    base: Omit<LogEntry, "decision" | "reason" | "forwarded" | "status" | "count">,
    decision: Decision,
    reason: ReasonCode,
    httpStatus: number,
    /** Operator-authored remediation hint from the matched policy rule. Static
     *  policy text (never request-derived), so log-safe; surfaced to the agent
     *  in the body and the `x-grenz-hint` header when present. */
    hint?: string,
    /** Wire mask: when present, the HTTP response carries THIS reason while the
     *  log row keeps the true `reason`. Used only by the decoy gates, so a
     *  toucher sees the generic response an innocent mistake would get and
     *  cannot tell a trap from an ordinary deny. */
    wireReason?: ReasonCode,
  ): Response {
    record({ ...base, decision, reason, forwarded: false, status: null, count: 0 });
    const wire = wireReason ?? reason;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-grenz-decision": decision,
      "x-grenz-reason": wire,
    };
    // Header values are Latin1; an operator hint may hold an em-dash/emoji/etc.
    // Fold to ASCII for the header (the full UTF-8 hint stays in the body below)
    // so a rich note can never turn a 403 deny into a 500 internal_error.
    if (hint) headers["x-grenz-hint"] = headerSafe(hint);
    return new Response(
      JSON.stringify({
        error: wire,
        decision,
        reason: wire,
        action: base.action,
        tool: base.tool,
        ...(hint ? { hint } : {}),
      }),
      { status: httpStatus, headers },
    );
  }

  /** What the approval gate decided: a blocking Response, or proceed —
   *  `remembered` distinguishes a reused decision from a fresh human one. */
  interface ApprovalGate {
    readonly response: Response | null;
    readonly remembered: boolean;
  }

  /**
   * Block on an approval. Returns `{response}` when the request must not
   * proceed (denied / expired / approvals unavailable), or `{response: null}`
   * when approved (the caller then falls through to budget + forward).
   *
   * `useMemory` gates the approval-memory shortcut: only STATIC-policy prompts
   * pass true. DLP-flagged and risk-step-up prompts always ask a human — those
   * exist because of dynamic context (body contents / behavior), so a
   * remembered "yes" must not cover a different secret or a new risk episode.
   *
   * `signal` is the request's abort signal. If the client disconnects while the
   * approval is pending, the pending approval is CANCELLED — so a human who
   * approves afterwards can no longer make the pipeline fetch a credential and
   * forward the action into a dead socket ("approved into the void").
   */
  async function awaitApproval(
    decided: Omit<LogEntry, "decision" | "reason" | "forwarded" | "status" | "count">,
    input: ApprovalInput,
    useMemory: boolean,
    signal: AbortSignal,
    quorum: number,
  ): Promise<ApprovalGate> {
    if (!deps.broker) {
      return {
        response: deny(decided, "require_approval", "approvals_unavailable", 403),
        remembered: false,
      };
    }
    const memory = useMemory ? deps.approvalMemory : undefined;
    const recalled = memory?.recall(input) ?? null;
    // Directional memory under quorum>1: a single remembered "yes" must NEVER
    // bypass dual-control, so a recalled approve is ignored when quorum>1. A
    // recalled DENY still short-circuits (sticky-deny stays — the anti-fatigue
    // defense must not be disabled on the most dangerous actions).
    if (recalled === "approved" && quorum <= 1) {
      emit(`[approval] remembered grant ${input.agentId} ${input.tool}:${input.action}`);
      return { response: null, remembered: true };
    }
    if (recalled === "denied") {
      emit(`[approval] remembered deny ${input.agentId} ${input.tool}:${input.action}`);
      return {
        response: deny(decided, "deny", "approval_remembered_deny", 403),
        remembered: true,
      };
    }
    // Hard cap on concurrent held approvals: bounds sockets/timers/memory so a
    // single agent cannot exhaust the proxy by queueing pending approvals.
    if (deps.broker.atCapacity()) {
      return { response: deny(decided, "deny", "approval_capacity", 429), remembered: false };
    }
    const { id, wait } = deps.broker.create(input, quorum);
    emit(
      `[approval] pending ${id} ${input.agentId} ${input.tool}:${input.action}` +
        (quorum > 1 ? ` (needs ${quorum} approvers)` : ""),
    );

    // A client that disconnects mid-approval must not have its action forwarded
    // later: wire the request's abort signal to CANCEL the pending approval, so
    // the blocking `await wait` below observes an "abandoned" outcome instead of
    // a (much later) human approval that would fetch a credential and forward
    // into a dead socket.
    const onAbort = (): void => {
      deps.broker?.cancel(id);
    };
    if (signal.aborted) onAbort(); // already gone; a {once:true} listener would never fire
    else signal.addEventListener("abort", onAbort, { once: true });

    const record = deps.broker.get(id);
    if (deps.notifier && record && !signal.aborted) {
      // Defensive: the Notifier contract forbids throwing, but a custom notifier
      // must never orphan the pending approval or fail the request.
      try {
        await deps.notifier.approvalRequested(record, `grenz approve ${id}`);
      } catch {
        emit(`[notify] notifier threw for ${id} (ignored)`);
      }
    }

    const outcome = await wait;
    signal.removeEventListener("abort", onAbort);
    // Close the loop on the notification channel (best-effort: never awaited, so
    // an approved outcome's forward isn't delayed by the round-trip, and never
    // throws into the pipeline). Fires only when a request was announced.
    if (deps.notifier?.approvalResolved && record) {
      void deps.notifier.approvalResolved(record, outcome).catch(() => {});
    }
    if (outcome.state === "abandoned") {
      emit(`[approval] abandoned ${id} (client disconnected)`);
      return {
        response: deny(decided, "deny", "approval_abandoned", denyStatus("approval_abandoned")),
        remembered: false,
      };
    }
    if (outcome.state === "approved") {
      // Belt-and-suspenders: a human approved in the same event-loop tick the
      // client vanished — still do not forward into a dead socket.
      if (signal.aborted) {
        emit(`[approval] abandoned ${id} (approved but client already gone)`);
        return {
          response: deny(decided, "deny", "approval_abandoned", denyStatus("approval_abandoned")),
          remembered: false,
        };
      }
      emit(`[approval] approved ${id} by ${outcome.decidedBy ?? "?"}`);
      // Never cache a dual-control approve: a quorum>1 decision must be earned
      // fresh every time (the deny direction below is still remembered).
      if (quorum <= 1) memory?.remember(input, "approved");
      return { response: null, remembered: false };
    }
    // A denial is remembered too (sticky deny closes retry-until-fatigue); an
    // EXPIRY is not a human decision and is never remembered.
    if (outcome.state === "denied") memory?.remember(input, "denied");
    const reason: ReasonCode = outcome.state === "denied" ? "approval_denied" : "approval_expired";
    return { response: deny(decided, "deny", reason, 403), remembered: false };
  }

  /**
   * `POST /delegate` — an agent (or a delegated sub-agent) mints an attenuated
   * child token for a sub-agent it is spawning. Authenticated with the minter's
   * own GRENZ_TOKEN. A delegated token MAY re-delegate, up to {@link MAX_DEPTH}
   * hops deep; the child inherits the chain's root agent and points at its
   * minter as the immediate parent. The child token is returned ONCE and never
   * logged. The scope requested here can only ever narrow — every child request
   * is re-checked as the intersection of the whole chain with the root's live
   * policy, so an over-broad request is harmless (it is clamped at use), not a
   * privilege grant.
   */
  async function handleDelegate(req: Request): Promise<Response> {
    if (req.method !== "POST") {
      return Response.json({ error: "method_not_allowed" }, { status: 405 });
    }
    if (!deps.delegations) {
      return Response.json({ error: "delegation_disabled" }, { status: 409 });
    }
    const { principal } = await resolvePrincipal(
      liveAgents(),
      deps.delegations,
      extractToken(req.headers),
      now(),
    );
    // An expired agent falls in here too: resolvePrincipal produced no principal,
    // so the existing generic 401 covers it (the log-side reason belongs to the
    // dispatch path; /delegate never mints for a non-identity).
    if (!principal) return Response.json({ error: "invalid_token" }, { status: 401 });
    // A decoy token must never be a delegation factory. Trip it here too, before
    // the revoked-check below (which would otherwise answer token_revoked on the
    // second attempt and distinguish the decoy). Same generic 401 as an unknown
    // token; fresh-dedups the notification.
    if (principal.kind === "agent" && principal.decoy) {
      const fresh = !(deps.revocations?.isRevoked(principal.agentId) ?? false);
      if (fresh) {
        deps.revocations?.revoke(principal.agentId, "decoy: token presented (delegate)", now());
        if (deps.notifier?.decoyTripped) {
          void deps.notifier.decoyTripped("token", principal.agentId, "-", "/delegate").catch(() => {});
        }
      }
      return Response.json({ error: "invalid_token" }, { status: 401 });
    }
    // Multi-hop: a delegated token MAY re-delegate, minting a grant one level
    // deeper. Refuse at the depth cap so a chain cannot grow without bound (the
    // resolver fails closed past the cap anyway; refusing here is the clear
    // early signal rather than minting a grant that can never resolve).
    if (principal.kind === "delegation" && principal.chainIds.length >= MAX_DEPTH) {
      return Response.json(
        { error: "delegation_depth", hint: `delegation chain is capped at ${MAX_DEPTH} hops` },
        { status: 403 },
      );
    }
    // A cut-off principal cannot mint fresh sub-tokens — local OR fleet, and over
    // the whole chain (any revoked ancestor). Children are already denied at the
    // dispatch gate, so this is a consistency guard (don't let a revoked identity
    // consume delegation capacity), not the last line of defence. Also refuse
    // while a stale fleet set has closed the proxy.
    const minterChainIds = principal.kind === "delegation" ? principal.chainIds : [];
    if (
      deps.revocations?.isRevoked(principal.agentId) ||
      minterChainIds.some((id) => deps.revocations?.isRevoked(id)) ||
      deps.fleetRevocations?.has(principal.agentId) === true ||
      minterChainIds.some((id) => deps.fleetRevocations?.has(id) === true) ||
      deps.revocationDistribution?.staleClosed === true
    ) {
      return Response.json({ error: "token_revoked" }, { status: 403 });
    }
    // Socket mode: /delegate is an agent route, so the admin listener refuses to
    // mint here too. Ordered exactly like the dispatch gate — after the decoy
    // gate above (a decoy trips whichever door it knocks on) and after the
    // kill-switch, so a revoked agent gets the authoritative token_revoked
    // instead of learning the topology and burning the one-shot notify slot.
    if (deps.agentRoutesEnabled === false) {
      // Recorded, not just notified: the notifier defaults to a no-op, and a
      // theft signal that leaves no trace is not a signal.
      record({
        ts: now(),
        agentId: principal.agentId,
        upstream: "-",
        tool: "-",
        action: "delegate",
        method: "POST",
        target: "/delegate",
        decision: "deny",
        reason: "wrong_listener",
        forwarded: false,
        status: null,
        count: 0,
      });
      if (!wrongListenerNotified.has(principal.agentId)) {
        wrongListenerNotified.add(principal.agentId);
        if (deps.notifier?.wrongListener) {
          void deps.notifier.wrongListener(principal.agentId, "-", "/delegate").catch(() => {});
        }
      }
      return Response.json({ error: "wrong_listener" }, { status: 403 });
    }
    if (deps.delegations.atCapacity(now())) {
      return Response.json({ error: "delegation_capacity" }, { status: 429 });
    }
    let rawBody: unknown;
    try {
      rawBody = await req.json();
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }
    const parsed = delegateRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      return Response.json(
        { error: "invalid_request", detail: parsed.error.issues[0]?.message },
        { status: 400 },
      );
    }
    const mintNow = now();
    const requestedTtlMs = (parsed.data.ttl_seconds ?? DEFAULT_TTL_SECONDS) * 1000;
    // The immediate parent is the minter's leaf grant (null for an agent mint).
    const parentDelegationId = principal.kind === "delegation" ? principal.delegationId : null;
    // A child can never outlive its immediate parent grant: clamp its TTL to the
    // parent's remaining life. For an agent mint there is no such bound (the
    // schema already caps the requested TTL).
    let ttlMs = requestedTtlMs;
    if (parentDelegationId !== null) {
      const parent = deps.delegations.get(parentDelegationId);
      // Raced with expiry/purge between auth and here → nothing live to mint under.
      if (!parent) return Response.json({ error: "token_revoked" }, { status: 403 });
      ttlMs = Math.min(requestedTtlMs, parent.expiresAt - mintNow);
      if (ttlMs <= 0) return Response.json({ error: "token_revoked" }, { status: 403 });
    }
    const { token, delegation } = await deps.delegations.mint({
      parentAgentId: principal.agentId,
      parentDelegationId,
      actions: parsed.data.actions,
      targets: parsed.data.targets,
      ttlMs,
      note: parsed.data.note ?? "",
      now: mintNow,
      policyProfile: principal.policyProfile,
    });
    emit(
      `[delegate] ${principal.agentId} minted ${delegation.id} ` +
        `(${delegation.actions.join(",")}` +
        (delegation.targets.length > 0 ? ` @ ${delegation.targets.join(",")}` : "") +
        `) ttl ${Math.round(ttlMs / 1000)}s` +
        (parentDelegationId ? ` under ${parentDelegationId}` : ""),
    );
    return Response.json({
      token,
      delegation_id: delegation.id,
      parent: delegation.parentAgentId,
      parent_delegation: delegation.parentDelegationId,
      actions: delegation.actions,
      targets: delegation.targets,
      expires_at: delegation.expiresAt,
    });
  }

  /**
   * `POST /exec` — the bash pre-action gate. See `exec-route.ts` for why the
   * decision lives in the daemon and which gates run.
   *
   * Every failure path denies: guard off, bad method, bad body, no parser,
   * unparseable command, undecidable command, scope, tripwire, engine, budget.
   * Only an explicit engine allow (or an approved require_approval) returns 200.
   */
  async function handleExec(req: Request): Promise<Response> {
    if (deps.execGuard !== true) {
      return Response.json({ error: "not_found", hint: "the bash guard is not enabled" }, { status: 404 });
    }
    if (req.method !== "POST") {
      return Response.json({ error: "method_not_allowed" }, { status: 405 });
    }

    const ts = now();
    const baseLog = {
      ts,
      agentId: AGENT_UNKNOWN,
      upstream: BASH_TOOL,
      tool: BASH_TOOL,
      action: "-",
      method: "exec",
      target: "-",
    };

    // --- Authenticate (identical to /u/*) ----------------------------------
    const { principal, expiredAgentId, orphanRootAgentId } = await resolvePrincipal(
      liveAgents(),
      deps.delegations ?? null,
      extractToken(req.headers),
      ts,
    );
    if (!principal) {
      if (expiredAgentId !== null) {
        return deny({ ...baseLog, agentId: expiredAgentId }, "deny", "agent_token_expired", 401, undefined, "invalid_token");
      }
      if (orphanRootAgentId !== null) {
        return deny({ ...baseLog, agentId: orphanRootAgentId }, "deny", "delegation_root_missing", 401, undefined, "invalid_token");
      }
      return deny(baseLog, "deny", "invalid_token", 401);
    }
    const agentId = principal.agentId;
    const sessionKey = principal.kind === "delegation" ? principal.delegationId : agentId;
    const authed = {
      ...baseLog,
      agentId,
      delegationId: principal.kind === "delegation" ? principal.delegationId : null,
    };

    // --- Decoy token -------------------------------------------------------
    if (principal.kind === "agent" && principal.decoy) {
      const fresh = !(deps.revocations?.isRevoked(agentId) ?? false);
      if (fresh) {
        deps.revocations?.revoke(agentId, "decoy: token presented (exec)", ts);
        if (deps.notifier?.decoyTripped) {
          void deps.notifier.decoyTripped("token", agentId, BASH_TOOL, "/exec").catch(() => {});
        }
      }
      return deny(authed, "deny", "decoy_token", 401, undefined, "invalid_token");
    }

    // --- Kill-switch -------------------------------------------------------
    // Local revocation of the actor OR any ancestor, fleet revocation, and the
    // stale-fleet closed state — same set the /u/* gate checks.
    const chainIds = principal.kind === "delegation" ? principal.chainIds : [];
    if (
      deps.revocations?.isRevoked(agentId) === true ||
      chainIds.some((id) => deps.revocations?.isRevoked(id) === true) ||
      deps.fleetRevocations?.has(agentId) === true ||
      chainIds.some((id) => deps.fleetRevocations?.has(id) === true)
    ) {
      return deny(authed, "deny", "token_revoked", 403);
    }
    if (deps.revocationDistribution?.staleClosed === true) {
      return deny(authed, "deny", "revocation_stale", 403);
    }

    // --- Wrong listener ----------------------------------------------------
    // /exec is an agent route: the admin (TCP) listener refuses it in socket
    // mode, exactly like /u/* and /delegate.
    if (deps.agentRoutesEnabled === false) {
      return deny(authed, "deny", "wrong_listener", 403);
    }

    // --- Body --------------------------------------------------------------
    let body: unknown;
    try {
      const raw = await req.text();
      if (raw.length > MAX_COMMAND_BYTES * 2) {
        return deny(authed, "deny", "exec_parse_failed", 400, "request body too large");
      }
      body = JSON.parse(raw);
    } catch {
      return deny(authed, "deny", "exec_parse_failed", 400, "body is not valid JSON");
    }
    const parsed = parseExecRequest(body);
    if ("error" in parsed) {
      return deny(authed, "deny", "exec_parse_failed", 400, parsed.error);
    }

    // --- Policy selection --------------------------------------------------
    const selected = deps.policyStore
      ? deps.policyStore.policyFor(principal.policyProfile)
      : deps.policy;
    if (selected === null) {
      return deny(authed, "deny", "agent_policy_unresolved", 403);
    }
    const policy = selected;

    // --- Adapter + scope + fold + tripwire + engine ------------------------
    const decision = decideExec(parsed.command, {
      parser: bashParserSync(),
      policy,
      principal,
      sessionKey,
      now: ts,
      spent: 0,
      ceiling: agentCeiling(policy, agentId),
      revoke: (target, reason, at) => deps.revocations?.revoke(target, reason, at),
      notifyTripwire: (actor, action, target, note) => {
        if (deps.notifier?.tripwireTripped) {
          void deps.notifier.tripwireTripped(actor, action, target, note).catch(() => {});
        }
      },
    });

    const decided = {
      ...authed,
      action: decision.verdict.action,
      target: decision.verdict.target,
    };

    if (decision.verdict.decision === "deny") {
      return deny(
        decided,
        "deny",
        decision.verdict.reason,
        denyStatus(decision.verdict.reason),
        decision.verdict.message,
      );
    }

    // Both budget ceilings, shared by the approval pre-gate and the main gate —
    // the same shape /u/* uses, counting the whole line's cost.
    const billable = decision.cost;
    const budgetDenyReason = (): ReasonCode | null => {
      const spent = deps.log.countAllowedSince(agentId, ts - BUDGET_WINDOW_MS);
      const { limit, override } = agentCeiling(policy, agentId);
      if (limit !== null && spent + billable > limit) {
        return override ? "agent_budget_exceeded" : "budget_exceeded";
      }
      if (principal.kind === "delegation" && policy.perDelegationActionsPerHour !== null) {
        const spentDelegation = deps.log.countAllowedSinceForDelegation(
          principal.delegationId,
          ts - BUDGET_WINDOW_MS,
        );
        if (!withinDelegationBudget(policy, spentDelegation, billable)) {
          return "delegation_budget_exceeded";
        }
      }
      if (policy.perUpstreamActionsPerHour.has(BASH_TOOL)) {
        const spentUpstream = deps.log.countAllowedSinceForUpstream(agentId, BASH_TOOL, ts - BUDGET_WINDOW_MS);
        if (!withinUpstreamBudget(policy, BASH_TOOL, spentUpstream, billable)) {
          return "upstream_budget_exceeded";
        }
      }
      return null;
    };

    // --- Approval ----------------------------------------------------------
    // Blocks on the broker this process owns — the reason the hook cannot make
    // this decision itself.
    let viaRemembered = false;
    if (decision.verdict.decision === "require_approval") {
      const overBudget = budgetDenyReason();
      if (overBudget) return deny(decided, "deny", overBudget, 429);
      const gate = await awaitApproval(
        decided,
        {
          agentId,
          upstream: BASH_TOOL,
          tool: BASH_TOOL,
          action: decision.verdict.action,
          target: decision.verdict.target,
          method: "exec",
          context: decision.verdict.message,
        },
        true,
        req.signal,
        decision.quorum,
      );
      if (gate.response) return gate.response;
      viaRemembered = gate.remembered;
    }

    // --- Budget ------------------------------------------------------------
    const overBudget = budgetDenyReason();
    if (overBudget) return deny(decided, "deny", overBudget, 429);

    // --- Allow -------------------------------------------------------------
    // Same labels /u/* uses, so `grenz status` and the console count an
    // approved shell command as granted rather than leaving it under the
    // pre-decision `approval_required`.
    const reason: ReasonCode =
      decision.verdict.decision === "require_approval"
        ? viaRemembered
          ? "approval_remembered_grant"
          : "approval_granted"
        : decision.verdict.reason;
    const verdict: ExecVerdict = { ...decision.verdict, decision: "allow", reason };
    record(execLogEntry({ ts, agentId, delegationId: authed.delegationId }, verdict, billable));
    return Response.json(verdict, {
      status: 200,
      headers: { "x-grenz-decision": "allow", "x-grenz-reason": verdict.reason },
    });
  }

  async function dispatch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // --- Non-upstream routes ------------------------------------------------
    if (url.pathname === "/healthz") {
      return Response.json({ status: "ok" });
    }
    if (url.pathname === "/console" || url.pathname.startsWith("/console/") || url.pathname === "/metrics") {
      return handleConsole(req, url, {
        log: deps.log,
        broker: deps.broker ?? null,
        revocations: deps.revocations ?? null,
        delegations: deps.delegations ?? null,
        grants: deps.grants ?? null,
        agentIds: liveAgents().map((a) => a.id),
        adminToken: deps.adminToken ?? null,
        tokenStore: deps.tokenStore ?? null,
        config: deps.config,
        policy: getPolicy(),
        canaryStore: deps.canaryStore ?? null,
        breakGlass: deps.breakGlass ?? null,
        notifier: deps.notifier,
        policyDistribution: deps.policyDistribution ?? null,
        fleetRevocations: deps.fleetRevocations ?? null,
        revocationDistribution: deps.revocationDistribution ?? null,
        policyStore: deps.policyStore ?? null,
        policyHistory: deps.policyHistory ?? null,
        policyPath: deps.policyPath ?? null,
        // A remotely-managed policy is read-only: a local edit would be
        // overwritten on the next pull, so the editor refuses it.
        policyEditable: !deps.config.policy_source,
        approvalMemory: deps.approvalMemory ?? null,
        agentStore: deps.agentStore ?? null,
        configPath: deps.configPath ?? null,
        configWriteLock: deps.configWriteLock ?? null,
        emit,
        now,
      });
    }
    if (url.pathname === "/delegate") {
      return handleDelegate(req);
    }
    if (url.pathname === "/exec") {
      return handleExec(req);
    }
    if (url.pathname === "/") {
      // Minimal and unauthenticated by design: deliberately no agent id,
      // on_behalf_of (PII), or upstream topology — those would be disclosure if
      // the operator binds Grenz to a non-loopback host.
      return Response.json({ service: "grenz", status: "ok" });
    }

    const route = matchUpstreamRoute(url);
    if (!route) {
      return Response.json({ error: "not_found", hint: "requests go to /u/<upstream>/..." }, { status: 404 });
    }

    const ts = now();
    const baseLog = {
      ts,
      agentId: AGENT_UNKNOWN,
      upstream: route.upstreamName,
      tool: route.upstreamName,
      action: "-",
      method: req.method,
      target: route.path,
    };

    // --- Authenticate -------------------------------------------------------
    // Resolve to a Principal: a first-class agent, or a delegation (a sub-agent
    // acting under a parent's attenuated scope). A delegation's agentId is the
    // PARENT — it shares the parent's policy and budget and dies with it.
    const { principal, expiredAgentId, orphanRootAgentId } = await resolvePrincipal(
      liveAgents(),
      deps.delegations ?? null,
      extractToken(req.headers),
      ts,
    );
    if (!principal) {
      // A matched-but-expired agent gets the SAME generic 401 as an unknown
      // token (wire masked as invalid_token), but the operator's log row carries
      // the distinct agent_token_expired reason and the agent id.
      if (expiredAgentId !== null) {
        return deny({ ...baseLog, agentId: expiredAgentId }, "deny", "agent_token_expired", 401, undefined, "invalid_token");
      }
      // Same masking for a sub-token whose root agent is gone: the operator sees
      // WHY (their delete/expire took effect), the caller sees a plain 401.
      if (orphanRootAgentId !== null) {
        return deny({ ...baseLog, agentId: orphanRootAgentId }, "deny", "delegation_root_missing", 401, undefined, "invalid_token");
      }
      return deny(baseLog, "deny", "invalid_token", 401);
    }
    const agentId = principal.agentId;
    // Taint-flow session identity: a delegated sub-agent has its own context
    // window, so it accumulates (and is gated by) its own facts — never its
    // parent's. First-class agents key on the agent id.
    const sessionKey = principal.kind === "delegation" ? principal.delegationId : agentId;
    // Pin scope: a delegation reads its own pins and those of EVERY ancestor —
    // each grant in the chain plus the root agent — so a fresh grant id cannot
    // escape a session pin set anywhere above it. The child still RECORDS only
    // under its own sessionKey below (attenuation — an ancestor never sees the
    // child's pins). Deliberately diverges from taint-flow's per-delegation
    // isolation — for pins, inheritance up the chain is the whole point.
    const pinScope =
      principal.kind === "delegation" ? [...principal.chainIds, principal.agentId] : [agentId];
    const authed = {
      ...baseLog,
      agentId,
      // Attribution for per-delegation budgets: rows keep agent_id = PARENT
      // (the shared-ceiling invariant is unchanged); delegated requests ALSO
      // carry their own id so their spend can be counted per sub-token.
      delegationId: principal.kind === "delegation" ? principal.delegationId : null,
    };

    // --- Decoy token --------------------------------------------------------
    // A GRENZ_TOKEN no legitimate workload holds. Presenting it is high-
    // confidence compromise. Placed BEFORE the kill-switch so every probe
    // forever returns the same masked 401 — if the kill-switch ran first, the
    // second probe would answer token_revoked and reveal that the first did
    // something. `fresh` dedups the revoke-write and the notification across a
    // noisy scanner; the wire is masked as a plain invalid_token.
    if (principal.kind === "agent" && principal.decoy) {
      const fresh = !(deps.revocations?.isRevoked(agentId) ?? false);
      if (fresh) {
        deps.revocations?.revoke(agentId, "decoy: token presented", ts);
        if (deps.notifier?.decoyTripped) {
          void deps.notifier.decoyTripped("token", agentId, route.upstreamName, route.path).catch(() => {});
        }
      }
      return deny(authed, "deny", "decoy_token", 401, undefined, "invalid_token");
    }

    // --- Kill-switch --------------------------------------------------------
    // A revoked principal is cut off before upstream resolution, policy, or any
    // credential fetch. Takes effect mid-flight: `grenz revoke` mutates this
    // same store instance, no restart needed. Revoking the ROOT agent cascades
    // to every delegation in its tree (they carry the root id); revoking any
    // single grant cuts off that grant and everything below it, leaving its
    // ancestors and siblings alive. Cascade is just checking every id in the
    // chain — no tree walk at revoke time.
    //
    // Local revocations (incl. tripwire auto-revokes and per-delegation) are
    // UNIONed with the signed fleet set. The two stores are consulted, never
    // merged: the fleet set can never un-revoke a locally-revoked id, so a
    // fired tripwire survives any fleet sync. Grant ids are opaque, so a
    // per-grant revocation is fleet-distributable just like an agent id. The
    // agent learns it is cut off, never from where the decision came.
    const chainIds = principal.kind === "delegation" ? principal.chainIds : [];
    const revokedId =
      (deps.revocations !== undefined &&
        (deps.revocations.isRevoked(agentId) || chainIds.some((id) => deps.revocations!.isRevoked(id)))) ||
      deps.fleetRevocations?.has(agentId) === true ||
      chainIds.some((id) => deps.fleetRevocations?.has(id) === true);
    if (revokedId) {
      return deny(authed, "deny", "token_revoked", 403);
    }
    // Fail-closed on a STALE fleet set (opt-in): deny everything until a fresh
    // signed set lands. A dedicated code (not a policy deny-all swap) keeps this
    // separately attributable and instantly reversible when a fresh set arrives.
    if (deps.revocationDistribution?.staleClosed === true) {
      return deny(authed, "deny", "revocation_stale", 403);
    }

    // --- Wrong listener -----------------------------------------------------
    // Socket mode: agent traffic belongs on the unix socket. A resolved identity
    // arriving on the admin listener is a misconfigured agent — or a stolen
    // token being replayed on the one door still open to the network. Placed
    // AFTER the decoy gate (a decoy must still trip, whichever door it knocks
    // on) and AFTER the kill-switch (an already-revoked agent gets the
    // authoritative token_revoked, and never spams this notifier).
    //
    // The identity is logged and the operator notified ONCE per agent per
    // process — but never auto-revoked: a legitimate agent whose config simply
    // still points at the TCP port would otherwise self-destruct.
    if (deps.agentRoutesEnabled === false) {
      if (!wrongListenerNotified.has(agentId)) {
        wrongListenerNotified.add(agentId);
        if (deps.notifier?.wrongListener) {
          void deps.notifier.wrongListener(agentId, route.upstreamName, route.path).catch(() => {});
        }
      }
      return deny(authed, "deny", "wrong_listener", 403);
    }

    // --- Resolve upstream ---------------------------------------------------
    const upstream: UpstreamConfig | undefined = upstreams[route.upstreamName];
    if (!upstream) {
      return deny(authed, "deny", "unknown_upstream", 403);
    }

    // --- Decoy upstream -----------------------------------------------------
    // An upstream no policy grants. Touching it is high-confidence compromise.
    // Placed before the adapter, the body read, and policy evaluation, so it
    // fires on ANY action (even a would-deny) and never reads an attacker-
    // controlled body. A decoy is deterministic compromise, so it CASCADES: the
    // revoke targets the ROOT agent (`agentId`), killing the whole token tree —
    // every sibling and descendant — not just the sub-token that tripped. For a
    // first-class agent, root == actor, so it revokes itself. The notifier still
    // names the ACTOR that tripped (sessionKey) so the operator sees who reached
    // for the decoy; the reason records it too. Masked on the wire as a plain
    // no_matching_allow. Every node in the tree dies at the kill-switch on its
    // next request (each checks the root id), so no per-node revoke is needed.
    // This return narrows `upstream` to a real upstream for the rest of dispatch.
    if (upstream.decoy === true) {
      const via = sessionKey !== agentId ? ` (via ${sessionKey})` : "";
      deps.revocations?.revoke(agentId, `decoy: upstream ${route.upstreamName} touched${via}`, ts);
      if (deps.notifier?.decoyTripped) {
        void deps.notifier.decoyTripped("upstream", sessionKey, route.upstreamName, route.path).catch(() => {});
      }
      return deny(authed, "deny", "decoy_upstream", 403, undefined, "no_matching_allow");
    }

    const adapter = adapterFor(upstream.type);
    if (!adapter) {
      return deny(authed, "deny", "internal_error", 500);
    }

    // --- Read body + map to action(s) --------------------------------------
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const body = hasBody ? new Uint8Array(await req.arrayBuffer()) : new Uint8Array(0);
    const adapterReq: AdapterRequest = {
      method: req.method,
      path: route.path,
      query: route.query,
      body,
      contentType: req.headers.get("content-type"),
    };
    const mapping = adapter.map(adapterReq);
    if (isUnsupported(mapping)) {
      return deny(authed, "deny", "unsupported_request", 400);
    }

    const withTarget = { ...authed, target: mapping.target, method: mapping.label };
    // The request's real (action, target) pairs. `mapping.target` is a DISPLAY
    // label only — for an MCP batch it is the synthetic `batch(N)`, which matches
    // no glob, so matching on it would silently disarm every target-scoped gate.
    // Every gate below walks `pairs` instead.
    const pairs: readonly ActionTarget[] = mapping.actions.map((action, i) => ({
      action,
      target: mapping.targets[i]!,
    }));

    // --- Agent scope (the root of every scope chain) -----------------------
    // A first-class agent may be confined in grenz.yaml on two axes: which
    // ACTIONS and which TARGETS its token may reach. That scope is the root
    // every delegation attenuates from, so it is checked for BOTH an agent and a
    // delegation (whose `agentActions`/`agentTargets` are its root agent's).
    // Empty = unrestricted (today's behavior). Action is checked before target —
    // the more specific signal — mirroring the delegation fold below.
    if (principal.agentActions.length > 0) {
      const beyond = mapping.actions.find(
        (a) => !principal.agentActions.some((pattern) => globMatch(pattern, a)),
      );
      if (beyond !== undefined) {
        return deny({ ...withTarget, action: beyond }, "deny", "agent_action_scope", 403);
      }
    }
    if (principal.agentTargets.length > 0) {
      // EVERY target the request touches has to be in scope — one out-of-scope
      // member denies the whole request, the same rule the action axis uses.
      const beyond = mapping.targets.find(
        (t) => !principal.agentTargets.some((pattern) => globMatch(pattern, t)),
      );
      if (beyond !== undefined) {
        return deny({ ...withTarget, target: beyond }, "deny", "agent_target_scope", 403);
      }
    }

    // --- Delegation attenuation (the fold) ---------------------------------
    // A delegated request's scope is the INTERSECTION of every grant in its
    // chain: an action is in scope only if EVERY hop matches it. The root's
    // live policy (evaluated below) is the other half, so the full scope is
    //   live_policy(root) ∩ grant₁ ∩ … ∩ grantₙ.
    // Intersection is monotone, so a widened intermediate hop grants nothing —
    // a narrower ancestor still has to match. We never merge patterns or test
    // one glob as a subset of another (that is where bugs live); we just require
    // every hop to match every requested action. First miss denies the batch.
    if (principal.kind === "delegation") {
      const beyond = mapping.actions.find(
        (a) => !principal.actionsChain.every((hop) => hop.some((pattern) => globMatch(pattern, a))),
      );
      if (beyond !== undefined) {
        return deny({ ...withTarget, action: beyond }, "deny", "delegation_scope", 403);
      }
      // Target attenuation, same intersection rule on the OTHER axis: a hop with
      // no targets is unrestricted; a hop that lists targets requires the request
      // target to match one of them. EVERY target the request touches must
      // satisfy EVERY hop that constrains it. A widened descendant grants nothing
      // — a narrower ancestor still gates. First miss denies the whole request.
      const blockedTarget = mapping.targets.find((t) =>
        principal.targetsChain.some(
          (hop) => hop.length > 0 && !hop.some((pattern) => globMatch(pattern, t)),
        ),
      );
      if (blockedTarget !== undefined) {
        return deny({ ...withTarget, target: blockedTarget }, "deny", "delegation_target_scope", 403);
      }
    }

    // --- Evaluate policy ----------------------------------------------------
    // Snapshot the live policy ONCE per request (it may be hot-reloaded between
    // requests via PolicyStore); a single request always sees one policy.
    //
    // Select the policy for THIS principal's profile. Sits AFTER the agent-scope
    // gates and the delegation fold (both above), BEFORE tripwires/engine — so
    // scope and fold still gate first and the intersection claim holds. The
    // closed slot (staleness) overrides every profile inside policyFor.
    const selected = deps.policyStore
      ? deps.policyStore.policyFor(principal.policyProfile)
      : deps.policy; // no store ⇒ today's single-policy behavior
    if (selected === null) {
      return deny(withTarget, "deny", "agent_policy_unresolved", 403);
    }
    const policy = selected;

    // --- Tripwire: a declared action/target whose mere ATTEMPT (even a
    // would-deny) trips the kill-switch. Checked before the engine and over
    // EVERY batched action, so nothing rides past it. The revoke CASCADES by
    // default (`on_trip: cascade`): it targets the ROOT agent (`agentId`),
    // killing the whole token tree — the tripping sub-token, its parent, and
    // every sibling. `on_trip: leaf` keeps the surgical behavior — revoke only
    // the actor (`sessionKey`) — for a softer heuristic wire an honest agent
    // might occasionally hit. For a first-class agent, root == actor either way,
    // so it revokes itself. The notifier always names the ACTOR that tripped;
    // the reason records the tripping sub-token when it differs from the root.
    for (const { action: a, target: t } of pairs) {
      const wire = matchTripwire(policy.tripwires, a, t);
      if (wire) {
        const revokeTarget = wire.onTrip === "leaf" ? sessionKey : agentId;
        const via = revokeTarget !== sessionKey ? ` (via ${sessionKey})` : "";
        deps.revocations?.revoke(revokeTarget, `tripwire: ${a}${wire.note ? ` — ${wire.note}` : ""}${via}`, ts);
        if (deps.notifier?.tripwireTripped) {
          void deps.notifier.tripwireTripped(sessionKey, a, t, wire.note).catch(() => {});
        }
        return deny({ ...withTarget, action: a, target: t }, "deny", "tripwire", 403, wire.note ?? undefined);
      }
    }

    let { result, action } = combine(policy, route.upstreamName, mapping.actions, mapping.targets);
    const decided = { ...withTarget, action };

    // --- Shadow-policy canary: preview a candidate against live traffic ------
    // One extra pure engine verdict; recorded where it diverges from the live
    // one (already computed above and never re-read). Side-effect-free w.r.t.
    // the live decision. Runs in every mode, including --shadow.
    if (deps.canaryPolicy && deps.canaryStore) {
      const cand = combine(deps.canaryPolicy, route.upstreamName, mapping.actions, mapping.targets);
      deps.canaryStore.observe(route.upstreamName, action, result.decision, cand.result.decision);
    }

    // The static rule's operator note (a require_approval `message`), captured
    // BEFORE any dynamic gate can overwrite `result`. Surfaced to the human
    // approver as context on the pending approval; never written to the log.
    const ruleMessage = result.message;
    // Distinct approvers this request needs (dual-control). The MAX over EVERY
    // batch member, from the RAW actions — the approval `input.action` gets
    // decorated with `[risk:high]` etc. Applies at EVERY human prompt (static +
    // dynamic gates) below.
    //
    // Not `action`: that is combine()'s single representative, and reading the
    // quorum off it let a batch buy its members a cheaper one. Two ways:
    // combine() returns the FIRST require_approval member, so a later member
    // needing 3 approvers rode the first one's 1; and an all-allow batch
    // collapses to the synthetic label `batch:N`, which matches no quorum
    // pattern at all, so anything a dynamic gate (flow, pin, step-up, overlay)
    // clamped afterwards settled on a single tap. Dual-control has to hold for
    // every action the request actually performs.
    let quorum = mapping.actions.reduce((n, a) => Math.max(n, approvalQuorum(policy, a)), 1);

    // Budget is counted in COST UNITS: each action costs actionCost() (default
    // 1; `budget.weights` can raise it). One HTTP request may carry an MCP batch
    // of several actions, so it bills the SUM — batching cannot dilute a
    // weighted action. No weights -> every cost is 1 -> == mapping.actions.length.
    const billable = mapping.actions.reduce((sum, a) => sum + actionCost(policy, a), 0);

    // --- JIT grants: an operator-widened allow, bounded by TTL. Never
    // overrides an explicit `deny` — only "no_matching_allow"/
    // "no_grant_for_tool" (a gap) or "require_approval" (a per-request human
    // check) can be widened. Early cutoff reuses the existing kill-switch: a
    // grant is inert once its own id is revoked, same as a delegation.
    let viaGrant = false;
    if (deps.grants && result.decision !== "allow" && result.reason !== "explicit_deny") {
      const active = deps.grants
        .list(ts)
        .filter((g) => g.agentId === agentId && !deps.revocations?.isRevoked(g.id));
      const matched = active.find((g) => g.actions.some((pattern) => globMatch(pattern, action)));
      if (matched) {
        result = { decision: "allow", reason: "jit_grant", matched: null, pattern: null };
        viaGrant = true;
      }
    }

    // --- Break-glass: a loud, time-boxed admin unlock. Turns a would-be engine
    // DENY into a fresh `require_approval` (quorum from the window, may be 1 —
    // the only thing that lowers a quorum). A human still taps; deny-by-default's
    // default is untouched. Runs AFTER combine() (sees the deny) and AFTER the
    // kill-switch/tripwire returns (a revoked/tripwired agent is already cut off).
    let breakGlassTag: string | null = null;
    if (deps.breakGlass && result.decision === "deny") {
      const active = deps.breakGlass
        .list(ts)
        .filter((w) => w.agentId === agentId && !deps.revocations?.isRevoked(w.id));
      // EVERY denied action in the batch must match the window's globs, or the
      // whole request stays denied — an action must never ride a window scoped to
      // a different action (combine() collapses a batch to one representative).
      const matched = active.find((w) =>
        mapping.actions.every((a) => w.actions.some((p) => globMatch(p, a))),
      );
      if (matched) {
        result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
        breakGlassTag = "break_glass";
        quorum = matched.quorum; // override policy quorum DOWNWARD
      }
    }

    if (result.decision === "deny" && !deps.shadow) {
      // Surface the matched rule's operator-authored remediation hint (if any)
      // so the agent learns why it was blocked and what to do instead.
      return deny(decided, "deny", result.reason, denyStatus(result.reason), result.message);
    }

    // --- Schedule windows: outside the configured window, clamp any non-deny
    // verdict to the schedule's on_closed action. A pure comparator over the
    // injectable clock; the engine stays clockless. Placed before shadow so
    // `--shadow` observes schedule would-blocks too.
    let scheduleTag: string | null = null;
    // A break-glass verdict suspends a closed business-hours schedule — the 3am
    // emergency is exactly what break-glass exists for, so the schedule gate must
    // not re-deny it. Only the deny-clamp is skipped; a require_approval schedule
    // still just carries its tag.
    if (policy.schedule && result.decision !== "deny" && !withinSchedule(policy.schedule, ts)) {
      if (policy.schedule.onClosed === "deny" && breakGlassTag === null) {
        if (!deps.shadow) return deny(decided, "deny", "schedule_closed", 403);
        result = { decision: "deny", reason: "schedule_closed", matched: null, pattern: null };
      } else if (breakGlassTag === null) {
        result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
        scheduleTag = "schedule:closed";
      }
    }

    // --- First-use gating: the FIRST time an agent forwards a gated action,
    // clamp the otherwise-permitted verdict to on_first. Behavioral novelty gate:
    // a forwarded-before read of the local log (operational memory, like
    // budgets) plus a pure in-scope test — the engine stays clockless. Inspects
    // EVERY batch member so a novel action can't ride inside a batch. Before
    // shadow so `--shadow` observes it and shadow forwards still seed.
    //
    // Guarded on `!== "deny"`, NOT `=== "allow"`: an already-clamped
    // require_approval (a closed schedule, a static require_approval rule) must
    // not swallow an `on_first: deny`. It used to — which turned a hard "never on
    // first use" into a prompt a human could nod through, exactly when the
    // schedule said the agent should not be working at all.
    //
    // Two verdicts ARE skipped, because each is already a human's explicit
    // decision about this specific action:
    //   - a JIT grant (`viaGrant`, not `result.reason` — a later clamp
    //     overwrites the reason but not the fact that a grant applied);
    //   - an open break-glass window, which exists precisely to permit the
    //     novel emergency action. The schedule gate skips its own deny-clamp
    //     for break-glass for the same reason.
    let firstUseTag: string | null = null;
    const fu = policy.firstUse;
    if (fu && result.decision !== "deny" && !viaGrant && breakGlassTag === null) {
      const since = fu.windowMs === null ? 0 : ts - fu.windowMs;
      const novel = mapping.actions.find(
        (a) =>
          firstUseInScope(fu, a) &&
          !deps.log.hasForwardedActionSince(agentId, route.upstreamName, a, since),
      );
      if (novel !== undefined) {
        if (fu.onFirst === "deny") {
          if (!deps.shadow) return deny({ ...withTarget, action: novel }, "deny", "first_use_denied", 403);
          result = { decision: "deny", reason: "first_use_denied", matched: null, pattern: null };
        } else {
          result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
          firstUseTag = "first_use";
        }
      }
    }

    // --- Risk-adaptive step-up: upgrade an ALLOW to require_approval when the
    // agent's recent activity scores "high". Reuses the same pure scoreRisk()
    // and synchronous log read `grenz risk` already uses — no new IO category,
    // no network, and the pure policy engine itself is untouched (this runs in
    // the proxy layer around it, same as the budget/DLP checks below).
    let stepUpTag: string | null = null;
    if (result.decision === "allow" && policy.stepUp) {
      const activity = deps.log.agentActivity(agentId, ts - policy.stepUp.windowMs);
      const risk = scoreRisk(activity);
      if (risk.level === "high") {
        result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
        stepUpTag = "risk:high";
      }
    }

    // --- Per-agent approval overlay: for this agent (the root agent for a
    // delegation), an allowed action matching the agent's overlay is clamped to
    // require_approval — friction added on top of the shared grants. Placed AFTER
    // schedule/first-use/step-up so it never MASKS one of their denies: first-use
    // is guarded on `decision === "allow"`, so an earlier clamp would swallow its
    // `on_first: deny` hard-deny (turning a hard deny into an approvable request).
    // Runs before flow/pin, which is fine — those are `!== "deny"` guarded and
    // still fire (and can still deny) on the clamped result. Iterates every
    // mapping.actions member so a match cannot hide inside an MCP batch. The pure
    // engine is untouched (a proxy-layer clamp, exactly like step-up above).
    //
    // Target axis: each pair carries its OWN target, so a target-scoped overlay
    // is matched exactly — no blanket clamp for batches, and no batch slipping
    // past a scoped rule either.
    let agentApprovalTag: string | null = null;
    if (
      result.decision === "allow" &&
      pairs.some((p) => agentRequiresApproval(policy, agentId, p.action, p.target))
    ) {
      result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
      agentApprovalTag = "agent";
    }

    // --- Taint-flow gate: escalate a non-deny verdict when this action is a
    // SINK and a matching SOURCE was seen within the flow's window for this
    // token-holder (the read->exfil "lethal trifecta" sequence). A proxy-layer
    // gate around the pure engine; the decision core (evaluateFlows) is pure.
    // Before shadow so `--shadow` observes it; never overrides an explicit deny.
    let flowTag: string | null = null;
    let flowContext: string | null = null;
    if (result.decision !== "deny" && policy.flows.length > 0 && deps.flowFacts) {
      const facts = deps.flowFacts.factsSince(sessionKey, ts - maxWithinMs(policy.flows));
      // Every batched member is a candidate SINK, and an earlier member is a
      // candidate SOURCE — evaluateFlowsBatch folds the request's own sources in
      // so a batch can neither hide a sink nor carry both halves for free.
      const batchHit = evaluateFlowsBatch(policy.flows, facts, pairs, ts);
      if (batchHit) {
        const { hit } = batchHit;
        flowContext = `triggered by \`${hit.source.action}\` earlier this session → now \`${batchHit.action}\``;
        if (hit.effect === "deny") {
          if (!deps.shadow) return deny(decided, "deny", "flow_denied", 403);
          result = { decision: "deny", reason: "flow_denied", matched: null, pattern: null };
        } else {
          result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
          flowTag = "flow";
        }
      }
    }

    // --- Pin gate: escalate when this session pivots to a target UNIT it has
    // not already touched with a matching action (lateral movement inside a
    // broad grant — the runtime dual of blast-radius). Proxy-layer wrapper;
    // evaluatePin is pure. Before shadow so `--shadow` observes it; never
    // overrides an explicit deny.
    let pinTag: string | null = null;
    let pinContext: string | null = null;
    if (result.decision !== "deny" && policy.pins.length > 0 && deps.pinFacts) {
      const facts = pinScope.flatMap((k) =>
        deps.pinFacts!.factsSince(k, ts - maxPinWithinMs(policy.pins)),
      );
      // Every batched member is measured, with the batch's own earlier units
      // folded in — a batch must not be a free lateral move.
      const hit = evaluatePinBatch(policy.pins, facts, pairs, ts);
      if (hit) {
        pinContext = `session pinned away from \`${hit.unit}\` (pin rule ${hit.ruleIndex})`;
        if (hit.effect === "deny") {
          if (!deps.shadow) return deny(decided, "deny", "pin_violation", 403);
          result = { decision: "deny", reason: "pin_violation", matched: null, pattern: null };
        } else {
          result = { decision: "require_approval", reason: "approval_required", matched: null, pattern: null };
          pinTag = "pin";
        }
      }
    }

    // --- Shadow mode: suppress the POLICY verdict only. A deny/require_approval
    // is remembered as the true verdict and the decision is rewritten to allow
    // so control falls through the SAME budget -> DLP -> vault -> forward path a
    // real allow takes — every credential-protecting gate on it stays enforced.
    // The forward record() below writes the true verdict back, tagged shadow.
    let shadowVerdict: { decision: Decision; reason: ReasonCode } | null = null;
    if (deps.shadow && (result.decision === "deny" || result.decision === "require_approval")) {
      shadowVerdict = { decision: result.decision, reason: result.reason };
      result = { decision: "allow", reason: "explicit_allow", matched: null, pattern: null };
    }

    // Both budget ceilings, in one place so the approval pre-gate and the main
    // gate agree. Returns the deny reason if either is exceeded, else null. The
    // scoped query runs only when this upstream actually has a ceiling, so the
    // common uncapped path keeps its single budget read.
    const budgetDenyReason = ():
      | "budget_exceeded"
      | "agent_budget_exceeded"
      | "delegation_budget_exceeded"
      | "upstream_budget_exceeded"
      | null => {
      // Agent ceiling: a per_agent entry OVERRIDES the global default for this
      // agent (higher or lower); unlisted agents fall back to the default.
      const spent = deps.log.countAllowedSince(agentId, ts - BUDGET_WINDOW_MS);
      const { limit, override } = agentCeiling(policy, agentId);
      if (limit !== null && spent + billable > limit) {
        return override ? "agent_budget_exceeded" : "budget_exceeded";
      }
      // Delegation ceiling: each delegated sub-token is individually capped so
      // a runaway child starves itself, not its parent or siblings. Additive:
      // the parent check above already counted this same spend. Skipped
      // entirely for first-class agents and when no ceiling is configured.
      if (principal.kind === "delegation" && policy.perDelegationActionsPerHour !== null) {
        const spentDelegation = deps.log.countAllowedSinceForDelegation(
          principal.delegationId,
          ts - BUDGET_WINDOW_MS,
        );
        if (!withinDelegationBudget(policy, spentDelegation, billable)) {
          return "delegation_budget_exceeded";
        }
      }
      if (policy.perUpstreamActionsPerHour.has(route.upstreamName)) {
        const spentUpstream = deps.log.countAllowedSinceForUpstream(
          agentId,
          route.upstreamName,
          ts - BUDGET_WINDOW_MS,
        );
        if (!withinUpstreamBudget(policy, route.upstreamName, spentUpstream, billable)) {
          return "upstream_budget_exceeded";
        }
      }
      return null;
    };

    let viaApproval = false;
    let viaRemembered = false;
    if (result.decision === "require_approval") {
      // Gate on budget BEFORE holding a human/socket: if the action could not be
      // allowed anyway, deny now rather than queueing a doomed approval.
      const overBudget = budgetDenyReason();
      if (overBudget) return deny(decided, "deny", overBudget, 429);
      // Block on a human decision (Gate 2). Denied/expired/unavailable end here;
      // an approval falls through to the same budget + forward path as an allow.
      const gate = await awaitApproval(
        decided,
        {
          agentId,
          upstream: route.upstreamName,
          tool: route.upstreamName,
          action: (agentApprovalTag ?? stepUpTag ?? scheduleTag ?? firstUseTag ?? flowTag ?? pinTag ?? breakGlassTag)
            ? `${action} [${agentApprovalTag ?? stepUpTag ?? scheduleTag ?? firstUseTag ?? flowTag ?? pinTag ?? breakGlassTag}]`
            : action,
          target: mapping.target,
          method: mapping.label,
          context: flowContext ?? pinContext ?? ruleMessage,
        },
        // Only a static-policy prompt may reuse a remembered decision; a
        // per-agent-overlay, risk-step-up, schedule-forced, first-use,
        // taint-flow, or pin prompt exists because of context, so it always asks.
        (agentApprovalTag ?? stepUpTag ?? scheduleTag ?? firstUseTag ?? flowTag ?? pinTag ?? breakGlassTag) === null,
        req.signal,
        quorum,
      );
      if (gate.response) return gate.response;
      viaApproval = true;
      viaRemembered = gate.remembered;
    }

    // --- Budget (in actions, so an MCP batch cannot evade it) --------------
    // Global ceiling AND, if configured, this upstream's own ceiling.
    const overBudget = budgetDenyReason();
    if (overBudget) return deny(decided, "deny", overBudget, 429);

    // --- Content inspection (DLP): scan the outbound body for secrets -------
    // A permitted action can still carry a bad payload. Only detector NAMES are
    // ever surfaced; the matched secret is never logged or returned.
    if (policy.dlp?.scanBodies && hasBody && body.byteLength > 0) {
      const findings = scanBytes(body);
      if (findings.length > 0) {
        const detectors = findingLabel(findings);
        emit(`[dlp] ${agentId} ${route.upstreamName}:${action} secret in body: ${detectors}`);
        if (policy.dlp.onMatch === "require_approval") {
          const gate = await awaitApproval(
            decided,
            {
              agentId,
              upstream: route.upstreamName,
              tool: route.upstreamName,
              action: `${action} [dlp:${detectors}]`,
              target: mapping.target,
              method: mapping.label,
              context: ruleMessage,
            },
            // DLP prompts never reuse a decision: the detector label can match
            // while the actual secret in the body differs.
            false,
            req.signal,
            quorum,
          );
          if (gate.response) return gate.response;
          viaApproval = true; // a human approved despite the finding
        } else {
          return deny(decided, "deny", "dlp_secret_detected", 403);
        }
      }
    }

    // --- Egress guard: the outbound request (which will carry the real
    // credential) must resolve to the upstream's exact configured origin. Runs
    // before the credential is even fetched, so a blocked request never
    // decrypts it. Deny-by-default on any off-origin resolution.
    const egress = resolveUpstreamUrl(upstream.base_url, route.path, route.query);
    if (!egress.ok) {
      return deny(decided, "deny", "egress_blocked", denyStatus("egress_blocked"));
    }

    // --- Fetch credential (fail closed) ------------------------------------
    let credential: string | undefined;
    try {
      credential = await deps.vault.get(upstream.credential);
    } catch (err) {
      const reason: ReasonCode = err instanceof VaultError ? "vault_error" : "internal_error";
      return deny(decided, "deny", reason, denyStatus(reason));
    }
    // A present-but-empty credential is effectively missing: never forward an
    // unauthenticated request dressed up as an allowed one.
    if (credential === undefined || credential.length === 0) {
      return deny(decided, "deny", "credential_missing", 502);
    }

    // Response size cap: the tightest across EVERY action in the batch (a batch
    // can't dodge a cap by bundling a capped read with an uncapped one). Pure.
    let responseLimit: ResolvedResponseLimit | null = null;
    for (const { action: a, target: t } of pairs) {
      const l = resolveResponseLimit(policy, a, t);
      if (l === null) continue;
      responseLimit =
        responseLimit === null ||
        l.maxBytes < responseLimit.maxBytes ||
        (l.maxBytes === responseLimit.maxBytes && l.onExceed === "deny")
          ? l
          : responseLimit;
    }

    // --- Forward ------------------------------------------------------------
    try {
      const fwd = await forward({
        upstream,
        credential,
        method: req.method,
        url: egress.url,
        requestHeaders: req.headers,
        body: hasBody ? body : null,
        responseLimit: responseLimit ?? undefined,
      });

      if (fwd.outcome === "too_large") {
        // Policy allowed the action, but the oversized body is refused
        // (on_exceed: deny). The request WAS sent upstream (a read side-effect
        // only — operators scope `on` to reads), so record forwarded:true with
        // the refusal reason. The agent receives NO body, so no taint/pin fact
        // is seeded (it loaded no context).
        emit(`[responses] ${agentId} ${route.upstreamName}:${action} response over ${responseLimit?.maxBytes}B cap — denied`);
        // A size-cap refusal is a REAL enforcement (like a DLP block), not a
        // shadow observation — it fires and returns 413 even under --shadow. Record
        // it as a real deny (shadow:false, count 0), matching how DLP denies log.
        record({
          ...decided,
          decision: "deny",
          reason: "response_too_large",
          forwarded: true,
          status: 413,
          count: 0,
          shadow: false,
        });
        return Response.json(
          { error: "response_too_large" },
          { status: 413, headers: { "x-grenz-decision": "deny", "x-grenz-reason": "response_too_large" } },
        );
      }

      const { response, status } = fwd;
      if (fwd.outcome === "truncated") {
        emit(`[responses] ${agentId} ${route.upstreamName}:${action} response truncated to ${responseLimit?.maxBytes}B cap`);
      }
      record({
        ...decided,
        decision: shadowVerdict ? shadowVerdict.decision : "allow",
        reason: shadowVerdict
          ? shadowVerdict.reason
          : viaApproval
            ? viaRemembered
              ? "approval_remembered_grant"
              : "approval_granted"
            : viaGrant
              ? "jit_grant"
              : "explicit_allow",
        forwarded: true,
        status,
        count: shadowVerdict ? 0 : billable, // shadow traffic is observational, never billed
        shadow: shadowVerdict !== null,
      });
      // Seed a taint fact when an allowed SOURCE action forwards, so a later
      // SINK in the same session is gated. Records under shadow too (so shadow
      // observes future gates). Never records credentials — action + target only.
      // Seeded per BATCH MEMBER with its own target, so a source that rode
      // inside a batch still taints the session for the next request.
      if (deps.flowFacts) {
        for (const { action: a, target: t } of pairs) {
          if (policy.flows.some((f) => f.when.some((p) => p.re.test(a)))) {
            deps.flowFacts.record(sessionKey, a, t, ts);
          }
        }
      }
      // Seed a pin fact when an allowed action that ESTABLISHES a pin forwards,
      // so a later pivot in the same session is gated. Records under the token-
      // holder's OWN sessionKey only (a delegation records its own; it inherited
      // the parent's above by reading). Records under shadow too. Unit + rule
      // index only — never credentials.
      if (deps.pinFacts) {
        for (const { action: a, target: t } of pairs) {
          for (const u of pinUnitsFor(policy.pins, a, t)) {
            deps.pinFacts.record(sessionKey, u.ruleIndex, u.unit, ts);
          }
        }
      }
      return response;
    } catch {
      // Forwarding threw before any response: the policy allowed the action but
      // it never reached the upstream, so it is marked not-forwarded and is NOT
      // billed (count 0). Do not surface the error object — it may reference the
      // injected credential header.
      record({
        ...decided,
        decision: shadowVerdict ? shadowVerdict.decision : "allow",
        reason: shadowVerdict ? shadowVerdict.reason : "upstream_error",
        forwarded: false,
        status: null,
        count: 0,
        shadow: shadowVerdict !== null,
      });
      return new Response(JSON.stringify({ error: "upstream_error", reason: "upstream_error" }), {
        status: 502,
        headers: { "content-type": "application/json", "x-grenz-reason": "upstream_error" },
      });
    }
  }

  return async function handle(req: Request): Promise<Response> {
    try {
      return await dispatch(req);
    } catch (err) {
      // Any unexpected throw fails closed on the response. record() never throws
      // (see above), so a logging failure cannot land here — meaning a forwarded
      // action is always logged before this catch could run.
      emit(`[error] internal_error (${err instanceof Error ? err.name : "unknown"})`);
      return new Response(JSON.stringify({ error: "internal_error", reason: "internal_error" }), {
        status: 500,
        headers: { "content-type": "application/json", "x-grenz-reason": "internal_error" },
      });
    }
  };
}

export interface StartedServer {
  readonly server: ReturnType<typeof Bun.serve>;
  readonly url: string;
  stop(): void;
}

/** Bun.serve caps `idleTimeout` at 255s. A `require_approval` request parks with
 *  no bytes flowing until a human decides, so the idle window must cover the
 *  approval TTL — otherwise Bun drops the connection (10s default) and the
 *  request is abandoned before the human can act. When the TTL exceeds what a
 *  held connection can cover, `capped` is true and the caller warns. */
export const BUN_IDLE_MAX_SECONDS = 255;
export const IDLE_BUFFER_SECONDS = 5;

export interface IdleTimeoutPlan {
  readonly idleTimeout: number;
  readonly capped: boolean;
}

export function approvalIdleTimeout(ttlSeconds: number): IdleTimeoutPlan {
  const desired = ttlSeconds + IDLE_BUFFER_SECONDS;
  return {
    idleTimeout: Math.min(BUN_IDLE_MAX_SECONDS, desired),
    capped: desired > BUN_IDLE_MAX_SECONDS,
  };
}

/** The banner's inline note for the `approvals:` line. When the TTL exceeds Bun's
 *  connection-hold ceiling (the shipped default 300s does), the agent's connection
 *  can't be parked for the full TTL — a slower decision drops it and the agent
 *  retries. This states that calmly in-context; an empty string when the TTL fits,
 *  so the common case adds no noise. Not an alarm above the banner. */
export function approvalHoldNote(ttlSeconds: number): string {
  return approvalIdleTimeout(ttlSeconds).capped
    ? ` (agent held ≤${BUN_IDLE_MAX_SECONDS}s — a slower decision drops the connection; the agent retries)`
    : "";
}

export function startServer(deps: ServerDeps): StartedServer {
  const handler = createHandler(deps);
  // The approval TTL can exceed Bun's 255s connection-hold ceiling (the shipped
  // default 300s does). That is a real but calm fact, not a misconfiguration, so
  // the CLI surfaces it inline on the banner's `approvals:` line rather than
  // alarming above the banner on every first run. See `approvalIdleTimeout`.
  const plan = approvalIdleTimeout(deps.config.approvals.ttl_seconds);
  const server = Bun.serve({
    hostname: deps.config.listen.host,
    port: deps.config.listen.port,
    idleTimeout: plan.idleTimeout,
    fetch: handler,
  });
  return {
    server,
    url: `http://${server.hostname}:${server.port}`,
    stop: () => server.stop(true),
  };
}

/**
 * Socket mode: serve AGENT routes on a unix domain socket. The caller must have
 * run `prepareSocket()` first (0700 directory, instance lock held, stale file
 * removed) and should call `finalizeSocket()` after this returns.
 *
 * `server.hostname`/`server.port` are `undefined` for a unix listener, so the
 * URL is built from the path — the TCP banner's `http://host:port` shape would
 * render "http://undefined:undefined" here.
 *
 * The approval idle-timeout warning is deliberately NOT emitted here: socket
 * mode also starts a TCP admin listener via `startServer`, which emits it once.
 */
export function startSocketServer(deps: ServerDeps, socketPath: string): StartedServer {
  const handler = createHandler(deps);
  const plan = approvalIdleTimeout(deps.config.approvals.ttl_seconds);
  // Bun's `unix` overload types `idleTimeout` as `undefined`, but the runtime
  // enforces it — measured identically against a TCP control (both dropped a
  // held request at the same point). Dropping the option to satisfy the types
  // would silently cap approvals on the socket at Bun's default, so the cast
  // preserves real behavior; revisit when the type is fixed upstream.
  const server = Bun.serve({
    unix: socketPath,
    idleTimeout: plan.idleTimeout,
    fetch: handler,
  } as unknown as Parameters<typeof Bun.serve>[0]);
  return {
    server,
    url: `unix://${socketPath}`,
    stop: () => server.stop(true),
  };
}
