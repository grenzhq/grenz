/**
 * Loopback console / admin API.
 *
 * Read-only visibility (summary, recent requests) plus the approval decision
 * endpoints. Everything here requires the admin token (`X-Grenz-Admin`), is
 * intended to be reached only over loopback, and exposes decision METADATA only
 * — never request bodies, headers, or credential material (invariant 5).
 *
 * The `grenz` CLI and the local Next.js console are both just clients of this
 * API; the pending-approval state lives in the proxy, so this is the only place
 * that can resolve a blocked request.
 */
import type { RequestLog } from "../log/request-log.ts";
import type { ApprovalBroker } from "../approvals/broker.ts";
import type { RevocationStore } from "../revoke/store.ts";
import type { FleetRevocationStore } from "../revocation/store.ts";
import type { RevocationDistributionState } from "../revocation/types.ts";
import {
  DelegationStore,
  DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS,
} from "../delegate/store.ts";
import {
  GrantStore,
  DEFAULT_TTL_SECONDS as GRANT_DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS as GRANT_MAX_TTL_SECONDS,
} from "../grant/store.ts";
import { constantTimeEqual, hashToken, generateToken } from "../util/token.ts";
import type { GrenzConfig } from "../config/schema.ts";
import { agentSchema, PROFILE_NAME_RE } from "../config/schema.ts";
import { addAgent } from "../config/rewrite.ts";
import { writeConfigAtomic, ConfigChangedError } from "../config/atomic-write.ts";
import type { AgentStore } from "../agents/store.ts";
import type { Mutex } from "../util/mutex.ts";
import type { CompiledPolicy } from "../policy/compile.ts";
import type { CanaryStore } from "../canary/store.ts";
import type { TokenStore } from "../admin/token-store.ts";
import { type Role, hasRole, requiredRole } from "../admin/role.ts";
import type { Notifier } from "../notify/notifier.ts";
import type { BreakGlassStore } from "../breakglass/store.ts";
import {
  DEFAULT_TTL_SECONDS as BG_DEFAULT_TTL_SECONDS,
  MAX_TTL_SECONDS as BG_MAX_TTL_SECONDS,
} from "../breakglass/store.ts";
import { agentCeiling } from "../policy/evaluate.ts";
import { scoreRisk } from "../risk/score.ts";
import { DEFENSE_CODES } from "../firewall/defenses.ts";
import { buildFirewallFeed } from "../firewall/feed.ts";
import { compilePolicyYaml } from "../policy/compile.ts";
import { policyEditorView, writeGrants } from "../policy/editor.ts";
import type { PolicyStore } from "../policy/store.ts";
import type { PolicyHistoryStore } from "../policy/history-store.ts";
import { z } from "zod";
import { writeFileSync, renameSync } from "node:fs";
import { createHash } from "node:crypto";

/** Structural shape of a POST /console/policy body. The real gate is
 *  compilePolicyYaml on the produced YAML — this only rejects wrong TYPES so a
 *  malformed request never reaches the round-trip. Entries are a union: a string
 *  action pattern or a target-scoped {action, targets} object. */
const grantEntrySchema = z.union([z.string(), z.record(z.string(), z.unknown())]);
const policyEditBodySchema = z.object({
  grants: z.array(
    z.object({
      tool: z.string(),
      allow: z.array(grantEntrySchema).default([]),
      require_approval: z.array(grantEntrySchema).default([]),
      deny: z.array(grantEntrySchema).default([]),
    }),
  ),
  dryRun: z.boolean().optional(),
  /** The sha256 of the source the edit was based on (from GET). Required for a
   *  real save: a mismatch means the file changed underneath — refuse rather
   *  than silently clobber the policy file. Not needed for a dryRun. */
  baseDigest: z.string().optional(),
});

/** Content digest of the policy source — the TOCTOU guard for edits. */
function policyDigest(source: string): string {
  return createHash("sha256").update(source).digest("hex");
}

/** A new agent id: lowercase slug, must start alphanumeric. Stricter than the
 *  config schema (which only requires min-length) — this keeps `-` (the
 *  AGENT_UNKNOWN log sentinel) and other odd ids out at the door. */
const agentMintBodySchema = z.object({
  id: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_-]{0,63}$/, "id must be a lowercase slug starting with a letter or digit"),
  /** Optional target globs confining the new agent's token (see agentSchema).
   *  Absent = unrestricted. Same cap as a delegated sub-token. */
  targets: z.array(z.string().min(1)).min(1).max(100).optional(),
  /** Optional action globs confining the new agent's token — the other scope
   *  axis. Absent = unrestricted. */
  actions: z.array(z.string().min(1)).min(1).max(100).optional(),
  /** Optional named policy profile governing this agent. Its EXISTENCE is checked
   *  against the live profiles in the handler (a key of policy_profiles the running
   *  proxy loaded) — the shape check here only rejects an obviously-malformed name. */
  policy: z.string().regex(PROFILE_NAME_RE, "policy must be a valid profile name").optional(),
});
import { analyzeBlastRadius } from "../blast-radius/analyze.ts";
import { buildExplain } from "../explain/report.ts";
import { collectExplainInputs } from "../explain/inputs.ts";
import { renderMetrics } from "../telemetry/metrics.ts";
import type { PolicyDistributionState } from "../distribution/types.ts";

const MAX_REASON = 200;
const MAX_NOTE = 200;

const SUMMARY_WINDOW_MS = 24 * 60 * 60 * 1000;
const BUDGET_WINDOW_MS = 60 * 60 * 1000; // mirrors the proxy's budget window
const RISK_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;

export interface ConsoleDeps {
  readonly log: RequestLog;
  readonly broker: ApprovalBroker | null;
  readonly revocations: RevocationStore | null;
  readonly delegations: DelegationStore | null;
  readonly grants: GrantStore | null;
  /** Configured agent ids — an admin may only mint a delegation for a real one. */
  readonly agentIds: readonly string[];
  /** The bootstrap admin token (plaintext, from admin.token) — an always-present
   *  admin identity named `bootstrap`. */
  readonly adminToken: string | null;
  /** Named admin tokens (roles). Null disables RBAC beyond the bootstrap token. */
  readonly tokenStore: TokenStore | null;
  /** Blast-radius analysis needs the full config (upstreams) and compiled policy. */
  readonly config: GrenzConfig;
  readonly policy: CompiledPolicy;
  /** Shadow-policy canary snapshot source. Null when no candidate is loaded. */
  readonly canaryStore: CanaryStore | null;
  /** Break-glass windows. Null disables the endpoints. */
  readonly breakGlass: BreakGlassStore | null;
  /** Notifier for the loud break-glass pull event (optional). */
  readonly notifier?: Notifier;
  /** Live signed-distribution state, read by reference so /metrics sees refresh
   *  updates. Absent when the policy is local (reported as version 0). */
  readonly policyDistribution?: PolicyDistributionState | null;
  /** Fleet kill-set (for the restore refusal). Absent = no fleet channel. */
  readonly fleetRevocations?: FleetRevocationStore | null;
  /** Live fleet-revocation state, read by reference for /metrics. */
  readonly revocationDistribution?: RevocationDistributionState | null;
  /** Live policy store (hot-reload seam). When present the console reads the
   *  CURRENT compiled policy through it (so edits show without a restart). */
  readonly policyStore?: PolicyStore | null;
  /** Policy version history — captured on a console edit for `grenz policy rollback`. */
  readonly policyHistory?: PolicyHistoryStore | null;
  /** Path to the local policy.yaml (the editable source). Absent = not editable. */
  readonly policyPath?: string | null;
  /** False when the policy is managed remotely (policy_source) — editor read-only. */
  readonly policyEditable?: boolean;
  /** Approval memory, cleared on a policy edit to mirror the --watch reload path. */
  readonly approvalMemory?: { clear(): void } | null;
  /** Live agent set — present enables `POST /console/agents` (minting a new
   *  agent that authenticates immediately). Absent = minting disabled. */
  readonly agentStore?: AgentStore | null;
  /** Path to the local grenz.yaml — the file a mint appends to. */
  readonly configPath?: string | null;
  /** Serializes grenz.yaml rewrites so two concurrent mints can't race. */
  readonly configWriteLock?: Mutex | null;
  /** Operational log sink (stderr). Used for the mint audit line — never a token. */
  readonly emit?: (line: string) => void;
  readonly now: () => number;
}

function unauthorized(): Response {
  return Response.json({ error: "unauthorized" }, { status: 401 });
}

function bearer(req: Request): string | null {
  const auth = req.headers.get("authorization");
  if (!auth) return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
  return m && m[1] ? m[1].trim() : null;
}

function forbidden(need: Role): Response {
  return Response.json({ error: "forbidden", required_role: need }, { status: 403 });
}

/** Resolve the presented admin credential to an operator identity. The bootstrap
 *  token (admin.token) is an always-present admin named `bootstrap`; otherwise a
 *  named token is matched by hash. Null = unauthenticated. */
async function authenticate(
  req: Request,
  bootstrapToken: string | null,
  tokenStore: TokenStore | null,
  now: number,
): Promise<{ name: string; role: Role; subject: string | null } | null> {
  const presented = req.headers.get("x-grenz-admin") ?? bearer(req);
  if (presented === null) return null;
  const presentedHash = await hashToken(presented);
  // Compare the bootstrap token the same way agent tokens are matched: over
  // equal-length hex digests. A raw plaintext compare short-circuits on length,
  // leaking the bootstrap token's length as a timing side-channel.
  if (bootstrapToken && constantTimeEqual(presentedHash, await hashToken(bootstrapToken))) {
    return { name: "bootstrap", role: "admin", subject: null };
  }
  return tokenStore ? tokenStore.resolve(presentedHash, now) : null;
}

export async function handleConsole(req: Request, url: URL, deps: ConsoleDeps): Promise<Response> {
  // Deny-by-default RBAC: authenticate the operator, then gate on the minimum
  // role the route requires (unrecognized routes require admin). Admin-plane
  // access control / separation of duties — NOT an audit surface.
  const identity = await authenticate(req, deps.adminToken, deps.tokenStore, deps.now());
  if (!identity) return unauthorized();
  const need = requiredRole(req.method, url.pathname);
  if (!hasRole(identity.role, need)) return forbidden(need);

  const path = url.pathname;
  // Read the LIVE compiled policy through the hot-reload store when present, so a
  // console policy edit is reflected everywhere without a restart.
  const livePolicy = deps.policyStore?.current ?? deps.policy;

  if (req.method === "GET" && path === "/console/summary") {
    const since = deps.now() - SUMMARY_WINDOW_MS;
    const stats = deps.log.summary(since);
    return Response.json({
      window_hours: 24,
      ...stats,
      pending: deps.broker?.pendingCount() ?? 0,
      would_block: deps.log.shadowWouldBlock(since),
    });
  }

  if (req.method === "GET" && path === "/metrics") {
    const now = deps.now();
    const s = deps.log.summary(0); // all-time (cumulative counters)
    const shadow = deps.log.shadowWouldBlock(0).reduce((n, r) => n + r.n, 0);
    return new Response(
      renderMetrics({
        decisions: { allow: s.allow, deny: s.deny },
        approvals: { granted: s.approvalGranted, denied: s.approvalDenied, expired: s.approvalExpired },
        approvalsPending: deps.broker?.pendingCount() ?? 0,
        delegationsActive: deps.delegations?.list(now).length ?? 0,
        grantsActive: deps.grants?.list(now).length ?? 0,
        agentsRevoked: deps.revocations?.list().length ?? 0,
        shadowWouldBlock: shadow,
        policyVersion: deps.policyDistribution?.version ?? 0,
        policySecondsSincePull:
          deps.policyDistribution && deps.policyDistribution.lastVerifiedPullAt > 0
            ? Math.max(0, Math.floor((now - deps.policyDistribution.lastVerifiedPullAt) / 1000))
            : 0,
        revocationsFleet: deps.revocationDistribution?.count ?? 0,
        revocationSetVersion: deps.revocationDistribution?.version ?? 0,
        revocationSecondsSincePull:
          deps.revocationDistribution && deps.revocationDistribution.lastVerifiedPullAt > 0
            ? Math.max(0, Math.floor((now - deps.revocationDistribution.lastVerifiedPullAt) / 1000))
            : 0,
      }),
      { headers: { "content-type": "text/plain; version=0.0.4" } },
    );
  }

  // --- Budget usage (read-only; same primitives the enforcement gate uses) --
  if (req.method === "GET" && path === "/console/budgets") {
    const since = deps.now() - BUDGET_WINDOW_MS;
    const capped = [...livePolicy.perUpstreamActionsPerHour.entries()];
    const agents = deps.agentIds.map((agent) => {
      const { limit, override } = agentCeiling(livePolicy, agent);
      return {
        agent,
        limit,
        override,
        spent: deps.log.countAllowedSince(agent, since),
        upstreams: capped.map(([upstream, uLimit]) => ({
          upstream,
          limit: uLimit,
          spent: deps.log.countAllowedSinceForUpstream(agent, upstream, since),
        })),
      };
    });
    return Response.json({ window_hours: 1, agents });
  }

  // --- Live risk levels (the `grenz risk` view over the admin API) --------
  if (req.method === "GET" && path === "/console/risk") {
    const since = deps.now() - RISK_WINDOW_MS;
    const agents = deps.agentIds.map((agent) => {
      const activity = deps.log.agentActivity(agent, since);
      const r = scoreRisk(activity);
      return {
        agent,
        level: r.level,
        score: r.score,
        reasons: r.reasons,
        total: activity.total,
        deny: activity.deny,
      };
    });
    return Response.json({ window_minutes: 15, agents });
  }

  // --- Shadow-policy canary snapshot (aggregate divergence metadata only) ---
  if (req.method === "GET" && path === "/console/canary") {
    if (!deps.canaryStore) return Response.json({ configured: false });
    return Response.json(deps.canaryStore.snapshot());
  }

  if (req.method === "GET" && path === "/console/requests") {
    const raw = Number(url.searchParams.get("limit") ?? DEFAULT_LIMIT);
    const limit = Number.isInteger(raw) ? Math.min(Math.max(raw, 1), MAX_LIMIT) : DEFAULT_LIMIT;
    return Response.json({ requests: deps.log.recent(limit) });
  }

  // --- Firewall activity (defense events, classified + coalesced) ----------
  // The last N requests the firewall actually STOPPED (or observed under
  // --shadow), each tagged with which defense fired. Reads the plain request
  // log filtered to defense reason codes — live visibility, never an audit
  // trail. Metadata only; a viewer token suffices (it is a GET read).
  if (req.method === "GET" && path === "/console/firewall") {
    const raw = Number(url.searchParams.get("limit") ?? DEFAULT_LIMIT);
    const limit = Number.isInteger(raw) ? Math.min(Math.max(raw, 1), MAX_LIMIT) : DEFAULT_LIMIT;
    const rows = deps.log.recentByReasons(DEFENSE_CODES, limit);
    return Response.json({ events: buildFirewallFeed(rows) });
  }

  // --- Policy editor (grants) ---------------------------------------------
  // GET returns the editable grants view + a content digest; POST validates a
  // proposed edit through the SAME compiler every policy uses and, only if it
  // compiles, writes it atomically and hot-reloads it. A remotely-managed
  // policy (policy_source) is read-only. Writes a control INPUT, not history.
  if (path === "/console/policy") {
    const editable = deps.policyEditable === true && typeof deps.policyPath === "string";

    if (req.method === "GET") {
      if (!editable) {
        // Remote/managed policy: no local source to edit. Grants are visible via
        // blast-radius; here we just report read-only.
        return Response.json({
          editable: false,
          grants: [],
          advancedSections: [],
          // Per-agent profiles are not shown in the default policy view (Slice 2/3);
          // surface the count so the default view is not quietly wrong.
          profilesActive: deps.policyStore?.profileNames.length ?? 0,
          // Stale-closed: the proxy is denying ALL requests (on_stale=fail_closed).
          // The default policy shown here is NOT what's being enforced right now.
          denyingAll: deps.policyStore?.isClosed ?? false,
        });
      }
      let source: string;
      try {
        source = await Bun.file(deps.policyPath!).text();
      } catch {
        return Response.json({ error: "policy_unreadable" }, { status: 500 });
      }
      let view;
      try {
        view = policyEditorView(source);
      } catch (err) {
        return Response.json(
          { error: "policy_parse_error", detail: err instanceof Error ? err.message : "parse failed" },
          { status: 500 },
        );
      }
      return Response.json({
        editable: true,
        grants: view.grants,
        advancedSections: view.advancedSections,
        digest: policyDigest(source),
        // Per-agent profiles are not shown in the default policy view (Slice 2/3);
        // surface the count so the default view is not quietly wrong.
        profilesActive: deps.policyStore?.profileNames.length ?? 0,
        // Stale-closed: the proxy is denying ALL requests (on_stale=fail_closed).
        // The default policy shown here is NOT what's being enforced right now.
        denyingAll: deps.policyStore?.isClosed ?? false,
      });
    }

    if (req.method === "POST") {
      if (!editable || !deps.policyStore) {
        return Response.json({ error: "policy_not_editable" }, { status: 409 });
      }
      const parsed = policyEditBodySchema.safeParse(await req.json().catch(() => null));
      if (!parsed.success) {
        return Response.json({ error: "invalid_request" }, { status: 400 });
      }
      const body = parsed.data;

      let source: string;
      try {
        source = await Bun.file(deps.policyPath!).text();
      } catch {
        return Response.json({ error: "policy_unreadable" }, { status: 500 });
      }

      // TOCTOU guard: a real save must be based on the source we last served.
      // A mismatch means the file changed underneath (a hand-edit, --watch, or
      // another tab) — refuse rather than clobber the policy file.
      if (!body.dryRun) {
        if (body.baseDigest !== policyDigest(source)) {
          return Response.json(
            { error: "stale_edit", grants: policyEditorView(source).grants, digest: policyDigest(source) },
            { status: 409 },
          );
        }
      }

      let candidate: string;
      try {
        candidate = writeGrants(source, body.grants);
      } catch (err) {
        return Response.json(
          { error: "policy_parse_error", detail: err instanceof Error ? err.message : "parse failed" },
          { status: 500 },
        );
      }

      // The one gate: compile through the real engine. Deny-by-default — an
      // invalid proposal is never written and the live policy is untouched.
      const compiled = compilePolicyYaml(candidate);
      if (!compiled.ok) {
        return Response.json({ error: "invalid_policy", detail: compiled.error }, { status: 400 });
      }
      if (body.dryRun) {
        return Response.json({ ok: true, valid: true, grants: compiled.policy.grants.size });
      }

      // Apply. Order fails closed at every leg: capture the version we're
      // replacing (best-effort, guarantees a rollback target), write atomically
      // (tmp+rename so a crash can't leave torn YAML), reload the already-
      // validated text (cannot fail — same input), clear remembered approvals
      // (parity with the --watch reload path), then capture the new version.
      deps.policyHistory?.record(source, deps.now());
      try {
        const tmp = `${deps.policyPath!}.tmp`;
        writeFileSync(tmp, candidate, { mode: 0o600 });
        renameSync(tmp, deps.policyPath!);
      } catch {
        return Response.json({ error: "policy_write_failed" }, { status: 500 });
      }
      const outcome = deps.policyStore.reload(candidate);
      deps.approvalMemory?.clear();
      deps.policyHistory?.record(candidate, deps.now());
      return Response.json({
        ok: true,
        grants: outcome.ok ? outcome.grants : compiled.policy.grants.size,
        previousGrants: outcome.ok ? outcome.previousGrants : undefined,
        digest: policyDigest(candidate),
      });
    }
  }

  // --- Mint a new agent (admin) -------------------------------------------
  // Create a first-class agent from the console: mint its GRENZ_TOKEN, persist
  // it to grenz.yaml, register it live (no restart), and return the raw token
  // exactly once. Admin-gated by the central role check above (deny-by-default).
  if (path === "/console/agents") {
    if (req.method === "GET") {
      // List live agents (id, profile, scope, expiry) — operational visibility for
      // the console + `grenz agents`. NEVER a token hash or any secret material.
      const agents = (deps.agentStore?.current ?? deps.config.agents).map((a) => ({
        id: a.id,
        policy: a.policy ?? null,
        actions: a.actions ?? [],
        targets: a.targets ?? [],
        decoy: a.decoy,
        expires_at: a.expiresAtMs !== null ? new Date(a.expiresAtMs).toISOString() : null,
      }));
      return Response.json({ agents });
    }
    if (req.method !== "POST") {
      return Response.json({ error: "method_not_allowed" }, { status: 405 });
    }
    if (!deps.agentStore || typeof deps.configPath !== "string" || !deps.configWriteLock) {
      return Response.json({ error: "agents_admin_disabled" }, { status: 409 });
    }
    const parsed = agentMintBodySchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) {
      return Response.json({ error: "invalid_request" }, { status: 400 });
    }
    const id = parsed.data.id;
    const targets = parsed.data.targets;
    const actions = parsed.data.actions;
    const policy = parsed.data.policy;
    // Fail closed: a named profile must exist in the LIVE profile set (a key of
    // policy_profiles the running proxy loaded). No store ⇒ no profiles ⇒ refuse,
    // rather than persist a `policy:` the next `grenz run` would reject.
    if (policy !== undefined && !(deps.policyStore?.profileNames.includes(policy) ?? false)) {
      return Response.json({ error: "unknown_profile" }, { status: 400 });
    }
    const store = deps.agentStore;
    const configPath = deps.configPath;
    const operator = identity.name;

    // The whole read → mint → write → register cycle runs under one lock, so two
    // concurrent mints can't both append the same id (which would brick the next
    // `grenz run` on the schema's duplicate-id check).
    return deps.configWriteLock.run(async () => {
      // Dup-check against the live store; the file rewrite below dup-checks the
      // yaml too (a `grenz decoy` from another process could add one out of band).
      if (store.has(id)) {
        return Response.json({ error: "agent_exists" }, { status: 409 });
      }
      let source: string;
      try {
        source = await Bun.file(configPath).text();
      } catch {
        return Response.json({ error: "config_unreadable" }, { status: 500 });
      }

      // Mint late: from here the raw token lives only in this frame — no error
      // path below interpolates it, and it is never logged.
      const token = generateToken();
      const hash = await hashToken(token);

      const rewrite = addAgent(source, id, hash, { actions, targets, ...(policy ? { policy } : {}) });
      if (!rewrite.ok) {
        const conflict = rewrite.error.includes("already exists");
        return Response.json(
          { error: conflict ? "agent_exists" : "config_invalid" },
          { status: conflict ? 409 : 500 },
        );
      }

      try {
        writeConfigAtomic(configPath, rewrite.yaml, source);
      } catch (err) {
        if (err instanceof ConfigChangedError) {
          return Response.json({ error: "config_changed" }, { status: 409 });
        }
        return Response.json({ error: "config_write_failed" }, { status: 500 });
      }

      // Persisted — register live. Schema-constructed so the in-memory shape can
      // never diverge from the restart shape. A rejection here means disk and
      // store disagree: an honest 500, never a compensating (racy) rewrite.
      const live = agentSchema.parse({
        id,
        token_hash: hash,
        ...(policy ? { policy } : {}),
        ...(actions ? { actions } : {}),
        ...(targets ? { targets } : {}),
      });
      const added = store.add(live);
      if (!added.ok) {
        return Response.json({ error: "agent_register_conflict" }, { status: 500 });
      }

      // Operational visibility only (no token material; not an audit trail).
      const scopeParts: string[] = [];
      if (actions && actions.length > 0) scopeParts.push(`actions ${actions.join(",")}`);
      if (targets && targets.length > 0) scopeParts.push(`targets ${targets.join(",")}`);
      const scopeNote = scopeParts.length > 0 ? ` scoped to ${scopeParts.join(" @ ")}` : "";
      const profileNote = policy ? ` [profile ${policy}]` : "";
      deps.emit?.(`[admin] agent "${id}" minted via console${scopeNote}${profileNote} (operator: ${operator})`);

      return new Response(
        JSON.stringify({
          id,
          token,
          ...(policy ? { policy } : {}),
          ...(actions ? { actions } : {}),
          ...(targets ? { targets } : {}),
        }),
        {
          status: 201,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        },
      );
    });
  }

  if (req.method === "GET" && path === "/console/approvals") {
    return Response.json({ approvals: deps.broker?.list() ?? [] });
  }

  const decide = /^\/console\/approvals\/([^/]+)\/(approve|deny)$/.exec(path);
  if (req.method === "POST" && decide) {
    const id = decodeURIComponent(decide[1]!);
    const action = decide[2]!;
    if (!deps.broker) return Response.json({ error: "approvals_disabled" }, { status: 409 });
    // Approver identity is the AUTHENTICATED token name — server-derived, never
    // client-asserted. This is what makes quorum a real separation-of-duties
    // control: distinct tokens = distinct approvers. A `by` in the body is ignored.
    const by = identity.name;
    if (action === "deny") {
      if (!deps.broker.deny(id, by)) return Response.json({ error: "not_found_or_settled" }, { status: 404 });
      return Response.json({ ok: true, id, decision: "deny", by });
    }
    const r = deps.broker.approveBy(id, by);
    if (r.status === "not_found") return Response.json({ error: "not_found_or_settled" }, { status: 404 });
    return Response.json({
      ok: true,
      id,
      decision: "approve",
      by,
      satisfied: r.status === "settled",
      approvals: r.approvals,
      quorum: r.quorum,
    });
  }

  // --- Explain (live per-action verdict) ----------------------------------
  // `grenz explain` over the RUNNING proxy's live state (budgets, grants,
  // kill-switch, hot-reloaded policy). Reuses the shared collector + buildExplain
  // so it can never diverge from the CLI / dispatch. Metadata only, admin-gated.
  if (req.method === "GET" && path === "/console/explain") {
    const tool = url.searchParams.get("tool");
    const action = url.searchParams.get("action");
    if (!tool || !action) {
      return Response.json({ error: "tool_and_action_required" }, { status: 400 });
    }
    const report = buildExplain(
      collectExplainInputs({
        policy: livePolicy,
        agentId: url.searchParams.get("agent") ?? livePolicy.agent,
        tool,
        action,
        target: url.searchParams.get("target"), // null when absent -> reachability
        now: deps.now(),
        log: deps.log,
        revocations: deps.revocations,
        grants: deps.grants,
        approvals: {
          ttlSeconds: deps.config.approvals.ttl_seconds,
          rememberSeconds: deps.config.approvals.remember_seconds,
        },
      }),
    );
    return Response.json(report);
  }

  // --- Blast-radius (static reachability analysis) ------------------------
  if (req.method === "GET" && path === "/console/blast-radius") {
    const agent = url.searchParams.get("agent") ?? livePolicy.agent;
    const now = deps.now();
    const report = analyzeBlastRadius({
      agent,
      upstreams: deps.config.upstreams,
      policy: livePolicy,
      delegations: (deps.delegations?.list(now) ?? []).map((d) => ({
        id: d.id,
        parentAgentId: d.parentAgentId,
        note: d.note,
        actions: d.actions,
        targets: d.targets,
        expiresAt: d.expiresAt,
      })),
      now,
    });
    return Response.json(report);
  }

  // --- Kill-switch (revocations) -----------------------------------------
  if (req.method === "GET" && path === "/console/revocations") {
    const revs = deps.revocations;
    if (!revs) {
      return Response.json({ enabled: false, revocations: [], agents: [], other: [] });
    }
    // A reason is machine-generated (an automatic cut-off) when it carries one
    // of the prefixes the proxy writes at the decoy/tripwire call sites.
    // Automaticity is a property of the RECORD, not the id shape: for a
    // top-level agent the decoy/tripwire session key IS its configured agent
    // id, so an auto-revoked agent must still be recognised here.
    const isAuto = (reason: string): boolean => /^(decoy|tripwire):/i.test(reason);
    const list = revs.list(); // local records, newest-first
    const agentSet = new Set(deps.agentIds);
    const agents = deps.agentIds.map((id) => {
      // `fleet` is computed for EVERY agent: enforcement denies on fleet
      // membership alone, with no local record — so a fleet-only agent is cut
      // off even though the local store is empty. `revoked = local || fleet`.
      const inFleet = deps.fleetRevocations?.has(id) === true;
      const rec = revs.get(id);
      if (rec) {
        return {
          id,
          revoked: true,
          local: true,
          fleet: inFleet,
          reason: rec.reason,
          ts: rec.ts,
          origin: isAuto(rec.reason) ? "auto" : "manual",
        };
      }
      return { id, revoked: inFleet, local: false, fleet: inFleet };
    });
    // Everything whose id is not a configured agent: delegation ids, session
    // keys, and stale/typo revocations. A different axis from "my agents".
    const other = list
      .filter((r) => !agentSet.has(r.agentId))
      .map((r) => ({ id: r.agentId, reason: r.reason, ts: r.ts, origin: isAuto(r.reason) ? "auto" : "manual" }));
    return Response.json({ enabled: true, revocations: list, agents, other });
  }

  const revoke = /^\/console\/revocations\/([^/]+)$/.exec(path);
  if (revoke && (req.method === "POST" || req.method === "DELETE")) {
    if (!deps.revocations) return Response.json({ error: "revocations_disabled" }, { status: 409 });
    const agentId = decodeURIComponent(revoke[1]!);
    if (req.method === "POST") {
      const reason = (url.searchParams.get("reason") ?? "manual").slice(0, MAX_REASON);
      const rec = deps.revocations.revoke(agentId, reason, deps.now());
      return Response.json({ ok: true, agent: agentId, reason: rec.reason, ts: rec.ts });
    }
    const removed = deps.revocations.restore(agentId);
    if (deps.fleetRevocations?.has(agentId) === true) {
      // Honest refusal: lifting the LOCAL revocation changes nothing while the
      // signed fleet set still cuts this agent off. Only a new signed set can
      // restore it. Report the true state rather than a hollow local success.
      return Response.json({
        ok: true,
        agent: agentId,
        removed,
        fleet_revoked: true,
        fleet_version: deps.revocationDistribution?.version ?? 0,
      });
    }
    return Response.json({ ok: true, agent: agentId, removed });
  }

  // --- Delegation (attenuated sub-tokens) --------------------------------
  if (path === "/console/delegations") {
    if (req.method === "GET") {
      const now = deps.now();
      const revocations = deps.revocations;
      const rows = (deps.delegations?.list(now) ?? []).map((d) => ({
        id: d.id,
        parent: d.parentAgentId,
        actions: d.actions,
        targets: d.targets,
        note: d.note,
        created_at: d.createdAt,
        expires_at: d.expiresAt,
        // Billable allowed actions this sub-token spent in the budget window —
        // computed with the same query the per-delegation gate uses.
        spent: deps.log.countAllowedSinceForDelegation(d.id, now - BUDGET_WINDOW_MS),
        // A delegation is dead if it (or its parent) has been revoked.
        revoked:
          revocations !== null &&
          (revocations.isRevoked(d.id) || revocations.isRevoked(d.parentAgentId)),
      }));
      return Response.json({ delegations: rows });
    }
    if (req.method === "POST") {
      // Admin mint on behalf of a configured agent (the operator/CLI path). The
      // agentic path is the token-authenticated POST /delegate on the proxy.
      if (!deps.delegations) return Response.json({ error: "delegation_disabled" }, { status: 409 });
      if (deps.delegations.atCapacity(deps.now())) {
        return Response.json({ error: "delegation_capacity" }, { status: 429 });
      }
      const agent = url.searchParams.get("agent");
      const actionsRaw = url.searchParams.get("actions");
      if (!agent || !actionsRaw) {
        return Response.json({ error: "missing_agent_or_actions" }, { status: 400 });
      }
      if (!deps.agentIds.includes(agent)) {
        return Response.json({ error: "unknown_agent" }, { status: 404 });
      }
      const actions = actionsRaw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      if (actions.length === 0) return Response.json({ error: "no_actions" }, { status: 400 });
      // Optional target scoping — restrict WHICH targets (repos/paths) the child
      // may reach. Absent = unrestricted by this grant (the root policy still gates).
      const targets = (url.searchParams.get("targets") ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const ttlReq = Number(url.searchParams.get("ttl") ?? DEFAULT_TTL_SECONDS);
      const ttl = Number.isFinite(ttlReq)
        ? Math.min(Math.max(Math.floor(ttlReq), 1), MAX_TTL_SECONDS)
        : DEFAULT_TTL_SECONDS;
      const note = (url.searchParams.get("note") ?? "").slice(0, MAX_NOTE);
      const { token, delegation } = await deps.delegations.mint({
        parentAgentId: agent,
        actions,
        targets,
        ttlMs: ttl * 1000,
        note,
        now: deps.now(),
        policyProfile: (deps.agentStore?.current ?? deps.config.agents).find((a) => a.id === agent)?.policy,
      });
      return Response.json({
        token,
        delegation_id: delegation.id,
        parent: delegation.parentAgentId,
        actions: delegation.actions,
        targets: delegation.targets,
        expires_at: delegation.expiresAt,
      });
    }
  }

  // --- Just-in-time temporary grants ---------------------------------------
  if (path === "/console/grants") {
    if (req.method === "GET") {
      const now = deps.now();
      const revocations = deps.revocations;
      const rows = (deps.grants?.list(now) ?? []).map((g) => ({
        id: g.id,
        agent: g.agentId,
        actions: g.actions,
        reason: g.reason,
        created_at: g.createdAt,
        expires_at: g.expiresAt,
        // A grant is dead once its own id has been revoked (the kill-switch's
        // early-cutoff path — see grant/store.ts's header comment).
        revoked: revocations !== null && revocations.isRevoked(g.id),
      }));
      return Response.json({ grants: rows });
    }
    if (req.method === "POST") {
      if (!deps.grants) return Response.json({ error: "grants_disabled" }, { status: 409 });
      if (deps.grants.atCapacity(deps.now())) {
        return Response.json({ error: "grant_capacity" }, { status: 429 });
      }
      const agent = url.searchParams.get("agent");
      const actionsRaw = url.searchParams.get("actions");
      if (!agent || !actionsRaw) {
        return Response.json({ error: "missing_agent_or_actions" }, { status: 400 });
      }
      if (!deps.agentIds.includes(agent)) {
        return Response.json({ error: "unknown_agent" }, { status: 404 });
      }
      const actions = actionsRaw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      if (actions.length === 0) return Response.json({ error: "no_actions" }, { status: 400 });
      const ttlReq = Number(url.searchParams.get("ttl") ?? GRANT_DEFAULT_TTL_SECONDS);
      const ttl = Number.isFinite(ttlReq)
        ? Math.min(Math.max(Math.floor(ttlReq), 1), GRANT_MAX_TTL_SECONDS)
        : GRANT_DEFAULT_TTL_SECONDS;
      const reason = (url.searchParams.get("reason") ?? "").slice(0, MAX_REASON);
      const grant = deps.grants.mint({
        agentId: agent,
        actions,
        ttlMs: ttl * 1000,
        reason,
        now: deps.now(),
      });
      return Response.json({
        grant_id: grant.id,
        agent: grant.agentId,
        actions: grant.actions,
        expires_at: grant.expiresAt,
      });
    }
  }

  // --- Named admin tokens (RBAC operators) — admin-only (central gate) ------
  // --- Break-glass windows — admin-only (central gate). A loud, time-boxed
  // unlock that turns a denied action into a fresh approval. Operational
  // emergency-access state, NOT an audit trail.
  if (path === "/console/break-glass") {
    if (!deps.breakGlass) return Response.json({ error: "break_glass_disabled" }, { status: 409 });
    if (req.method === "GET") {
      const now = deps.now();
      return Response.json({
        windows: deps.breakGlass.list(now).map((w) => ({
          id: w.id,
          agent: w.agentId,
          actions: w.actions,
          quorum: w.quorum,
          reason: w.reason,
          pulled_by: w.pulledBy,
          expires_at: w.expiresAt,
        })),
      });
    }
    if (req.method === "POST") {
      if (deps.breakGlass.atCapacity(deps.now())) {
        return Response.json({ error: "break_glass_capacity" }, { status: 429 });
      }
      const agent = url.searchParams.get("agent");
      const actionsRaw = url.searchParams.get("actions");
      if (!agent || !actionsRaw) return Response.json({ error: "missing_agent_or_actions" }, { status: 400 });
      if (!deps.agentIds.includes(agent)) return Response.json({ error: "unknown_agent" }, { status: 404 });
      const actions = actionsRaw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      if (actions.length === 0) return Response.json({ error: "no_actions" }, { status: 400 });
      const quorumRaw = Number(url.searchParams.get("quorum") ?? 1);
      const quorum = Number.isFinite(quorumRaw) ? Math.max(1, Math.floor(quorumRaw)) : 1;
      const ttlReq = Number(url.searchParams.get("ttl") ?? BG_DEFAULT_TTL_SECONDS);
      const ttl = Number.isFinite(ttlReq)
        ? Math.min(Math.max(Math.floor(ttlReq), 1), BG_MAX_TTL_SECONDS)
        : BG_DEFAULT_TTL_SECONDS;
      const reason = (url.searchParams.get("reason") ?? "").slice(0, MAX_REASON);
      const rec = deps.breakGlass.pull({
        agentId: agent,
        actions,
        quorum,
        reason,
        pulledBy: identity.name,
        ttlMs: ttl * 1000,
        now: deps.now(),
      });
      if (deps.notifier?.breakGlassPulled) {
        void deps.notifier
          .breakGlassPulled(rec.agentId, rec.actions, rec.pulledBy, rec.reason, rec.expiresAt)
          .catch(() => {});
      }
      return Response.json({
        id: rec.id,
        agent: rec.agentId,
        actions: rec.actions,
        quorum: rec.quorum,
        pulled_by: rec.pulledBy,
        expires_at: rec.expiresAt,
      });
    }
  }

  if (path === "/console/tokens") {
    if (!deps.tokenStore) return Response.json({ error: "tokens_unavailable" }, { status: 409 });
    if (req.method === "GET") {
      return Response.json({
        tokens: deps.tokenStore
          .list()
          .map((t) => ({ name: t.name, role: t.role, createdAt: t.createdAt, revokedAt: t.revokedAt })),
      });
    }
    if (req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as { name?: unknown; role?: unknown };
      const name = typeof body.name === "string" ? body.name.trim() : "";
      const role = body.role;
      if (!name) return Response.json({ error: "name_required" }, { status: 400 });
      if (role !== "viewer" && role !== "approver" && role !== "admin") {
        return Response.json({ error: "invalid_role" }, { status: 400 });
      }
      try {
        const { token, record } = await deps.tokenStore.create(name, role, deps.now());
        return Response.json({ name: record.name, role: record.role, token });
      } catch (err) {
        return Response.json({ error: err instanceof Error ? err.message : "create_failed" }, { status: 409 });
      }
    }
  }
  const tokenMatch = /^\/console\/tokens\/([^/]+)$/.exec(path);
  if (tokenMatch && req.method === "DELETE") {
    if (!deps.tokenStore) return Response.json({ error: "tokens_unavailable" }, { status: 409 });
    const name = decodeURIComponent(tokenMatch[1]!);
    return deps.tokenStore.revoke(name, deps.now())
      ? Response.json({ ok: true, name })
      : Response.json({ error: "not_found" }, { status: 404 });
  }

  return Response.json({ error: "not_found" }, { status: 404 });
}
