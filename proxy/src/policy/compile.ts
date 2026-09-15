/**
 * Compile a YAML policy source into a deterministic, precompiled rule object.
 *
 * Compilation is where all validation lives. The output (`CompiledPolicy`) is
 * a plain data structure the pure evaluator can consume without any further
 * parsing, network access, or error handling. Any failure here resolves to a
 * structured error so the caller can fail closed (DENY / refuse to start).
 */
import { parse as parseYaml } from "yaml";
import { policySchema, type PolicySource } from "./schema.ts";
import { compileGlob } from "./glob.ts";

export interface CompiledPattern {
  /** The original pattern text, for observability (never a secret). */
  readonly source: string;
  readonly re: RegExp;
}

/** A per-agent approval overlay rule: an action matcher plus optional target
 *  globs (null = any target). No `message` — the overlay adds approval friction,
 *  it is not a deny-with-hint. */
export interface CompiledApprovalRule {
  readonly action: CompiledPattern;
  readonly targets: readonly CompiledPattern[] | null;
}

export interface CompiledRule {
  /** The action pattern this rule matches. */
  readonly action: CompiledPattern;
  /** Target globs; the rule matches only when one matches the request's
   *  target. null = unconstrained (bare-string rule) — any target. */
  readonly targets: readonly CompiledPattern[] | null;
  /** Operator-authored remediation hint, surfaced to the agent as a `hint` when
   *  this rule produces a deny. Static policy text (never request-derived), so
   *  it is log-safe like `action.source`. null when unset. */
  readonly message: string | null;
  /** ALLOW rules only. What to do when this rule's action matches but the
   *  request's target could not be resolved statically (`curl $URL`): `deny`
   *  (the default, and today's behaviour) or `approve` — ask a human, because
   *  the action is known even though the argument is not. Never `approve` on a
   *  deny or require_approval rule; the schema rejects the key there. */
  readonly onUnresolved: "deny" | "approve";
}

export interface CompiledGrant {
  readonly tool: string;
  /** Evaluated in this order; deny wins, then approval, then allow. */
  readonly deny: readonly CompiledRule[];
  readonly requireApproval: readonly CompiledRule[];
  readonly allow: readonly CompiledRule[];
}

export interface CompiledDlp {
  readonly scanBodies: boolean;
  readonly onMatch: "deny" | "require_approval";
}

export interface CompiledWeight {
  readonly pattern: CompiledPattern;
  readonly weight: number;
}

export interface CompiledQuorum {
  readonly pattern: CompiledPattern;
  /** Distinct approvers required for a matching action (>= 2). */
  readonly n: number;
}

export type Weekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";
export interface CompiledScheduleWindow {
  readonly days: ReadonlySet<Weekday>;
  readonly startMin: number; // minutes since midnight, inclusive
  readonly endMin: number; // minutes since midnight, exclusive
}
export interface CompiledSchedule {
  readonly timezone: string;
  readonly windows: readonly CompiledScheduleWindow[];
  readonly onClosed: "deny" | "require_approval";
}

export interface CompiledFirstUse {
  readonly onFirst: "deny" | "require_approval";
  /** Action patterns this gate applies to; empty = all actions. */
  readonly only: readonly CompiledPattern[];
  /** Lookback in ms, or null for "ever". */
  readonly windowMs: number | null;
}

export interface CompiledFlow {
  /** Taint-source action patterns. */
  readonly when: readonly CompiledPattern[];
  /** Sink action patterns gated once a source was seen within the window. */
  readonly then: readonly CompiledPattern[];
  readonly effect: "deny" | "require_approval";
  /** Source-fact lifetime in ms. */
  readonly withinMs: number;
}

export interface CompiledTripwire {
  readonly action: CompiledPattern;
  /** Target globs; null = any target. */
  readonly targets: readonly CompiledPattern[] | null;
  readonly note: string | null;
  /** Blast radius when a delegated sub-token trips: `cascade` revokes the root
   *  (whole tree), `leaf` revokes only the tripping sub-token. */
  readonly onTrip: "cascade" | "leaf";
}

export interface CompiledPin {
  /** Compiled `key` regex; capture group 1 = the pin unit. */
  readonly key: RegExp;
  /** Action globs that establish + are constrained by the pin. */
  readonly on: readonly CompiledPattern[];
  readonly effect: "require_approval" | "deny";
  /** Pinned-unit lifetime in ms. */
  readonly withinMs: number;
}

export interface CompiledResponseRule {
  /** Action globs this cap applies to. */
  readonly on: readonly CompiledPattern[];
  /** Target globs; null = any target. */
  readonly targets: readonly CompiledPattern[] | null;
  readonly maxBytes: number;
  readonly onExceed: "truncate" | "deny";
}

export interface CompiledPolicy {
  readonly agent: string;
  readonly onBehalfOf: string;
  readonly grants: ReadonlyMap<string, CompiledGrant>;
  readonly maxActionsPerHour: number | null;
  /** Per-upstream hourly ceilings, keyed by upstream/tool name. Empty when unset. */
  readonly perUpstreamActionsPerHour: ReadonlyMap<string, number>;
  /** Per-agent hourly ceilings, keyed by agent id. OVERRIDE maxActionsPerHour for
   *  the named agents. Empty when unset. */
  readonly perAgentActionsPerHour: ReadonlyMap<string, number>;
  /** Per-agent approval overlay: action-glob matchers that, for the named agent,
   *  clamp an allowed action to require_approval. Keyed by agent id. Empty when
   *  unset. */
  readonly perAgentApproval: ReadonlyMap<string, readonly CompiledApprovalRule[]>;
  /** Hourly ceiling applied to EACH delegated sub-token individually (ids are
   *  ephemeral, so one number, not a map). Additive on top of the parent's
   *  agent ceiling. null = no per-token cap. */
  readonly perDelegationActionsPerHour: number | null;
  /** Per-action budget cost overrides; empty when unset. Default cost is 1. */
  readonly budgetWeights: readonly CompiledWeight[];
  /** Per-action approver quorums; empty when unset. Default quorum is 1. */
  readonly quorums: readonly CompiledQuorum[];
  readonly dlp: CompiledDlp | null;
  readonly stepUp: { readonly windowMs: number } | null;
  readonly schedule: CompiledSchedule | null;
  readonly firstUse: CompiledFirstUse | null;
  /** Taint-flow rules; empty when unset. */
  readonly flows: readonly CompiledFlow[];
  readonly pins: readonly CompiledPin[];
  /** Tripwire patterns; empty when unset. */
  readonly tripwires: readonly CompiledTripwire[];
  /** Response-size caps; empty when unset. */
  readonly responses: readonly CompiledResponseRule[];
  /** The validated source, retained for summaries and round-tripping. */
  readonly source: PolicySource;
}

export type CompileResult =
  | { readonly ok: true; readonly policy: CompiledPolicy }
  | { readonly ok: false; readonly error: string };

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

type RuleSource =
  | string
  | {
      readonly action: string;
      readonly targets?: readonly string[];
      readonly message?: string;
      readonly on_unresolved?: "deny" | "approve";
    };

function compileRules(rules: readonly RuleSource[], caseInsensitiveTargets = false): CompiledRule[] {
  return rules.map((r) =>
    typeof r === "string"
      ? { action: { source: r, re: compileGlob(r) }, targets: null, message: null, onUnresolved: "deny" }
      : {
          action: { source: r.action, re: compileGlob(r.action) },
          targets:
            r.targets && r.targets.length > 0
              ? r.targets.map((t) => ({ source: t, re: compileGlob(t, caseInsensitiveTargets) }))
              : null,
          message: r.message ?? null,
          // Defaults to today's behaviour: an unresolved target denies.
          onUnresolved: r.on_unresolved ?? "deny",
        },
  );
}

type ApprovalRuleSource = string | { readonly action: string; readonly targets?: readonly string[] };

/** Compile per-agent approval overlay rules: same null-vs-array target
 *  convention as `compileRules`, minus `message`. A bare string → any target. */
function compileApprovalRules(rules: readonly ApprovalRuleSource[]): CompiledApprovalRule[] {
  return rules.map((r) =>
    typeof r === "string"
      ? { action: { source: r, re: compileGlob(r) }, targets: null }
      : {
          action: { source: r.action, re: compileGlob(r.action) },
          // The overlay is an escalation (allow → require_approval), so its
          // targets match case-insensitively (fail-safe, can't be dodged).
          targets:
            r.targets && r.targets.length > 0
              ? r.targets.map((t) => ({ source: t, re: compileGlob(t, true) }))
              : null,
        },
  );
}

function toMinutes(hhmm: string): number {
  const [h, m] = hhmm.split(":");
  return Number(h) * 60 + Number(m);
}

type ScheduleSource = {
  readonly timezone: string;
  readonly windows: readonly { readonly days: readonly Weekday[]; readonly start: string; readonly end: string }[];
  readonly on_closed: "deny" | "require_approval";
};

function compileSchedule(
  src: ScheduleSource,
): { readonly ok: true; readonly schedule: CompiledSchedule } | { readonly ok: false; readonly error: string } {
  try {
    // Validating side effect: an unknown IANA name throws RangeError here.
    new Intl.DateTimeFormat("en-US", { timeZone: src.timezone });
  } catch {
    return { ok: false, error: `malformed policy: invalid schedule timezone "${src.timezone}"` };
  }
  const windows: CompiledScheduleWindow[] = [];
  for (const w of src.windows) {
    const startMin = toMinutes(w.start);
    const endMin = toMinutes(w.end);
    if (startMin >= endMin) {
      return { ok: false, error: `malformed policy: schedule window start "${w.start}" must be before end "${w.end}"` };
    }
    windows.push({ days: new Set(w.days), startMin, endMin });
  }
  return { ok: true, schedule: { timezone: src.timezone, windows, onClosed: src.on_closed } };
}

/** Compile an already-parsed object (used by tests and the YAML path). */
export function compilePolicyObject(input: unknown): CompileResult {
  const parsed = policySchema.safeParse(input);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? ` at \`${first.path.join(".")}\`` : "";
    const detail = first ? first.message : "invalid policy";
    return { ok: false, error: `malformed policy${where}: ${detail}` };
  }

  const source = parsed.data;
  const grants = new Map<string, CompiledGrant>();
  for (const grant of source.grants) {
    if (grants.has(grant.tool)) {
      return { ok: false, error: `malformed policy: duplicate grant for tool "${grant.tool}"` };
    }
    grants.set(grant.tool, {
      tool: grant.tool,
      // Protective clauses (deny, require_approval) match targets
      // case-insensitively so a mis-cased request can't dodge them; the allow
      // list stays case-sensitive (exact scoping, no over-allow).
      deny: compileRules(grant.deny, true),
      requireApproval: compileRules(grant.require_approval, true),
      allow: compileRules(grant.allow),
    });
  }

  let schedule: CompiledSchedule | null = null;
  if (source.schedule) {
    const compiled = compileSchedule(source.schedule);
    if (!compiled.ok) return { ok: false, error: compiled.error };
    schedule = compiled.schedule;
  }

  const firstUse: CompiledFirstUse | null = source.first_use
    ? {
        onFirst: source.first_use.on_first,
        only: source.first_use.only.map((p) => ({ source: p, re: compileGlob(p) })),
        windowMs: source.first_use.window_seconds ? source.first_use.window_seconds * 1000 : null,
      }
    : null;

  // Pins compile fail-loud: a malformed or keyless `key` would silently disable
  // the gate, so a bad one is a policy error (deny-by-default posture).
  const pins: CompiledPin[] = [];
  for (const p of source.pins) {
    let key: RegExp;
    try {
      // Case-INSENSITIVE, for the same reason scoped target globs are at every
      // other escalation site: a pin that fails to match its target goes INERT,
      // and an inert pin is fail-OPEN — a mis-cased path prefix (`/REPOS/...`)
      // would silently unpin the session and licence the lateral move the rule
      // exists to catch. The extracted unit itself is still compared verbatim,
      // so a case-shifted unit escalates rather than merging with the pinned
      // one: worst case is extra friction, never a bypass.
      key = new RegExp(p.key, "i");
    } catch (err) {
      return { ok: false, error: `malformed policy: pin key is not a valid regex: ${errorMessage(err)}` };
    }
    // Require ≥1 capture group (the pin unit). `new RegExp(src + "|")` matches
    // the empty string, so the result array length minus 1 is the group count.
    if (new RegExp(p.key + "|").exec("")!.length - 1 < 1) {
      return {
        ok: false,
        error: `malformed policy: pin key "${p.key}" has no capture group (need one to extract the pin unit)`,
      };
    }
    pins.push({
      key,
      on: p.on.map((g) => ({ source: g, re: compileGlob(g) })),
      effect: p.effect,
      withinMs: p.within_seconds * 1000,
    });
  }

  return {
    ok: true,
    policy: {
      agent: source.agent,
      onBehalfOf: source.on_behalf_of,
      grants,
      maxActionsPerHour: source.budget?.max_actions_per_hour ?? null,
      perUpstreamActionsPerHour: new Map(Object.entries(source.budget?.per_upstream ?? {})),
      perAgentActionsPerHour: new Map(Object.entries(source.budget?.per_agent ?? {})),
      perAgentApproval: new Map(
        Object.entries(source.approvals?.per_agent ?? {}).map(([id, rules]) => [
          id,
          compileApprovalRules(rules),
        ]),
      ),
      perDelegationActionsPerHour: source.budget?.per_delegation ?? null,
      budgetWeights: Object.entries(source.budget?.weights ?? {}).map(([glob, weight]) => ({
        pattern: { source: glob, re: compileGlob(glob) },
        weight,
      })),
      quorums: Object.entries(source.quorum ?? {}).map(([glob, n]) => ({
        pattern: { source: glob, re: compileGlob(glob) },
        n,
      })),
      dlp: source.dlp ? { scanBodies: source.dlp.scan_bodies, onMatch: source.dlp.on_match } : null,
      stepUp: source.step_up ? { windowMs: source.step_up.window_seconds * 1000 } : null,
      schedule,
      firstUse,
      flows: (source.flows ?? []).map((f) => ({
        when: f.when.map((p) => ({ source: p, re: compileGlob(p) })),
        then: f.then.map((p) => ({ source: p, re: compileGlob(p) })),
        effect: f.effect,
        withinMs: f.within_seconds * 1000,
      })),
      tripwires: (source.tripwires ?? []).map((t) => ({
        action: { source: t.action, re: compileGlob(t.action) },
        // Tripwire is an escalation (revoke): targets match case-insensitively.
        targets: t.targets ? t.targets.map((g) => ({ source: g, re: compileGlob(g, true) })) : null,
        note: t.note ?? null,
        onTrip: t.on_trip ?? "cascade",
      })),
      pins,
      responses: (source.responses ?? []).map((r) => ({
        on: r.on.map((g) => ({ source: g, re: compileGlob(g) })),
        // Response cap is protective: targets match case-insensitively.
        targets: r.targets ? r.targets.map((t) => ({ source: t, re: compileGlob(t, true) })) : null,
        maxBytes: r.max_bytes,
        onExceed: r.on_exceed,
      })),
      source,
    },
  };
}

/** Parse YAML text, then compile. Any parse or validation failure is captured. */
export function compilePolicyYaml(yamlText: string): CompileResult {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (err) {
    return { ok: false, error: `malformed policy: YAML parse error: ${errorMessage(err)}` };
  }
  if (parsed === null || parsed === undefined) {
    return { ok: false, error: "malformed policy: empty document" };
  }
  return compilePolicyObject(parsed);
}
