/**
 * Zod schema for the Grenz policy source (YAML → object → validated).
 *
 * `.strict()` everywhere: an unknown key is a malformed policy, and a malformed
 * policy fails closed (DENY) rather than being silently ignored. This is a
 * deliberate security property, not pedantry.
 */
import { z } from "zod";

/** A single action pattern, e.g. `repo:read`, `pr:*`, `actions:*`. */
const actionPattern = z.string().min(1);
/** A target glob matched against the request's log-safe target (path/label). */
const targetPattern = z.string().min(1);
/** A rule: a bare action pattern (any target), or an object with the action,
 *  optional target globs, and an optional operator-authored remediation message
 *  (static text, surfaced to the agent as a `hint` on a matching deny). */
const ruleSchema = z.union([
  actionPattern,
  z
    .object({
      action: actionPattern,
      targets: z.array(targetPattern).min(1).optional(),
      message: z.string().min(1).max(280).optional(),
    })
    .strict(),
]);

/**
 * An `allow` rule, which additionally accepts `on_unresolved`.
 *
 * Some targets cannot be resolved statically — `curl $URL` names a decidable
 * ACTION (`exec:curl`) whose argument is only known at run time. An unresolved
 * target can never satisfy a target glob, so such a command falls through this
 * rule and denies. `on_unresolved: approve` says "ask a human instead".
 *
 * It is a separate schema from `ruleSchema` on purpose: `.strict()` then makes
 * `on_unresolved` on a `deny` or `require_approval` clause a malformed policy,
 * which fails closed, rather than a silently inert key. The field is meaningless
 * there — a deny does not need permission to be unprovable.
 */
const allowRuleSchema = z.union([
  actionPattern,
  z
    .object({
      action: actionPattern,
      targets: z.array(targetPattern).min(1).optional(),
      message: z.string().min(1).max(280).optional(),
      on_unresolved: z.enum(["deny", "approve"]).optional(),
    })
    .strict(),
]);

export const grantSchema = z
  .object({
    tool: z.string().min(1),
    allow: z.array(allowRuleSchema).default([]),
    deny: z.array(ruleSchema).default([]),
    require_approval: z.array(ruleSchema).default([]),
  })
  .strict();

export const budgetSchema = z
  .object({
    max_actions_per_hour: z.number().int().positive().optional(),
    per_upstream: z.record(z.string().min(1), z.number().int().positive()).optional(),
    per_agent: z.record(z.string().min(1), z.number().int().positive()).optional(),
    per_delegation: z.number().int().positive().optional(),
    /** Per-action cost overrides for budget accounting; action glob -> cost
     *  (positive int, capped to catch typos). Unlisted actions cost 1. */
    weights: z.record(z.string().min(1), z.number().int().positive().max(1_000_000)).optional(),
  })
  .strict();

/** Per-agent approval overlay. For each named agent, an allowed action matching
 *  one of these globs is clamped to require_approval — friction-only, added on
 *  top of the shared grants without replacing them. Keyed by agent id. */
/** A per-agent approval rule: a bare action pattern (any target), or an object
 *  with the action and optional target globs. Mirrors the grant `ruleSchema`
 *  but WITHOUT `message` — the overlay produces require_approval, not a
 *  deny-with-hint, so `.strict()` rejects a stray `message` key (malformed →
 *  DENY) rather than silently ignoring it. A bare string stays valid, so
 *  policies written before target-scoping parse unchanged. */
const approvalRuleSchema = z.union([
  actionPattern,
  z
    .object({
      action: actionPattern,
      targets: z.array(targetPattern).min(1).optional(),
    })
    .strict(),
]);

export const approvalsSchema = z
  .object({
    per_agent: z
      .record(z.string().min(1), z.array(approvalRuleSchema).min(1).max(100))
      .optional(),
  })
  .strict();

export const dlpSchema = z
  .object({
    /** Scan outbound request bodies for credential shapes before forwarding. */
    scan_bodies: z.boolean().default(true),
    /** What to do when a secret is found in the body. */
    on_match: z.enum(["deny", "require_approval"]).default("deny"),
  })
  .strict();

const HHMM = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, "must be HH:MM (24-hour)");
const WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const scheduleWindowSchema = z
  .object({
    days: z.array(z.enum(WEEKDAYS)).min(1),
    start: HHMM,
    end: HHMM,
  })
  .strict();

export const scheduleSchema = z
  .object({
    /** IANA timezone the windows are interpreted in (e.g. America/New_York). */
    timezone: z.string().min(1).default("UTC"),
    windows: z.array(scheduleWindowSchema).min(1),
    /** What to do when the request falls outside every window. */
    on_closed: z.enum(["deny", "require_approval"]).default("deny"),
  })
  .strict();

export const stepUpSchema = z
  .object({
    /** How far back to look when scoring the agent's recent risk. */
    window_seconds: z.number().int().min(60).max(3600).default(900),
  })
  .strict();

export const firstUseSchema = z
  .object({
    /** What to do the first time an agent exercises a gated action. */
    on_first: z.enum(["deny", "require_approval"]).default("require_approval"),
    /** Action globs to gate — REQUIRED (≥1). Scope to capabilities worth a
     *  human's eyes on first use (e.g. "*:delete", "pr:merge", "call:*"); do NOT
     *  gate session/handshake plumbing, or a fresh agent stalls behind approvals. */
    only: z.array(z.string().min(1)).min(1),
    /** Optional lookback; omitted/absent = the whole local log's lifetime. */
    window_seconds: z.number().int().positive().optional(),
  })
  .strict();

export const flowSchema = z
  .object({
    /** Taint SOURCES — action globs whose (allowed, forwarded) use taints the
     *  session (e.g. reads of attacker-influenceable content). */
    when: z.array(z.string().min(1)).min(1),
    /** SINKS — action globs gated once any source was seen within the window
     *  (e.g. external writes / comms). */
    then: z.array(z.string().min(1)).min(1),
    /** What to do when a sink fires with a live source. */
    effect: z.enum(["deny", "require_approval"]).default("require_approval"),
    /** How long a source keeps tainting, in seconds. */
    within_seconds: z.number().int().min(1).max(86400).default(3600),
  })
  .strict();

export const tripwireSchema = z
  .object({
    /** Action glob whose mere attempt trips the kill-switch. */
    action: z.string().min(1),
    /** Optional target globs; omit = any target. */
    targets: z.array(z.string().min(1)).min(1).optional(),
    /** Optional operator note, shown to the human on trip. */
    note: z.string().min(1).max(280).optional(),
    /** Blast radius of the auto-revoke when a DELEGATED sub-token trips this
     *  wire. `cascade` (default) revokes the ROOT agent — killing the whole
     *  token tree, every sibling and descendant at once. `leaf` revokes only the
     *  sub-token that tripped, leaving its parent and siblings alive (surgical,
     *  for a softer heuristic tripwire an honest agent might occasionally hit).
     *  For a first-class agent (no delegation) both are identical: it revokes
     *  itself. Decoys have no such knob — a decoy is deterministic compromise, so
     *  it always cascades. */
    on_trip: z.enum(["cascade", "leaf"]).default("cascade"),
  })
  .strict();

export const pinSchema = z
  .object({
    /** Regex over the request target; capture group 1 = the pin UNIT (the thing
     *  the session pins to, e.g. `owner/repo`). Must have ≥1 capture group. */
    key: z.string().min(1),
    /** Action globs that both ESTABLISH a pin (on allowed forward) and are
     *  CONSTRAINED by it (a pivot to a new unit escalates). Reads/list/search
     *  are simply left out, so pinning governs only the mutating side named. */
    on: z.array(z.string().min(1)).min(1),
    /** What a pivot to a new unit does. */
    effect: z.enum(["require_approval", "deny"]).default("require_approval"),
    /** How long a pinned unit stays pinned, in seconds. */
    within_seconds: z.number().int().min(1).max(86400).default(3600),
  })
  .strict();

export const responseSchema = z
  .object({
    /** Action globs this response cap applies to (≥1). Reads left out of every
     *  `on` are uncapped. */
    on: z.array(z.string().min(1)).min(1),
    /** Optional target globs (default: all). Cap a broad read tighter for
     *  sensitive paths. */
    targets: z.array(z.string().min(1)).min(1).optional(),
    /** Byte cap on the response body. Bounded so a fat-fingered value is not
     *  absurd; the lower bound keeps it a real count. */
    max_bytes: z.number().int().min(1).max(1_000_000_000),
    /** truncate (default): stream up to max_bytes then cut. deny: refuse an
     *  oversized response — fail-fast only when the upstream declares a
     *  content-length; otherwise degrades to truncation. */
    on_exceed: z.enum(["truncate", "deny"]).default("truncate"),
  })
  .strict();

export const policySchema = z
  .object({
    agent: z.string().min(1),
    on_behalf_of: z.string().min(1),
    grants: z.array(grantSchema).default([]),
    budget: budgetSchema.optional(),
    approvals: approvalsSchema.optional(),
    dlp: dlpSchema.optional(),
    step_up: stepUpSchema.optional(),
    schedule: scheduleSchema.optional(),
    first_use: firstUseSchema.optional(),
    /** Actions that need N DISTINCT human approvers (separation of duties by
     *  convention): an action glob -> required approvers (2–16). Unlisted
     *  actions need 1. The approver id is a self-asserted label, not an
     *  authenticated identity — see the approvals docs' trust model. */
    quorum: z.record(z.string().min(1), z.number().int().min(2).max(16)).optional(),
    /** Taint-flow rules: gate a SINK action when a matching SOURCE action was
     *  seen within the window for the same token-holder (the "lethal trifecta"
     *  read->exfil sequence). Cross-tool by design. */
    flows: z.array(flowSchema).optional(),
    /** Tripwires: action/target patterns whose mere ATTEMPT (even a would-deny)
     *  revokes the actor via the kill-switch. A deterministic hair-trigger. */
    tripwires: z.array(tripwireSchema).optional(),
    /** Session target-pinning: once a session touches a target unit with a
     *  matching action, a pivot to a NEW unit escalates. The runtime dual of
     *  blast-radius — constrains lateral movement inside a broad grant. */
    pins: z.array(pinSchema).default([]),
    /** Response minimization: cap the BYTE size of an allowed response body. The
     *  read-side dual of request-body DLP — least-data-in. Counts bytes and cuts
     *  the stream; never inspects/buffers content (SSE-safe). */
    responses: z.array(responseSchema).default([]),
  })
  .strict();

export type PolicySource = z.infer<typeof policySchema>;
export type GrantSource = z.infer<typeof grantSchema>;
