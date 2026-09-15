/**
 * Blast-Radius Analyzer — static reachability analysis over live policy.
 *
 * Answers "if this agent's GRENZ_TOKEN leaks right now, what can actually be
 * done with it?" by expanding each upstream's glob grants against that
 * upstream type's known action vocabulary. Pure and synchronous — no IO, no
 * network, no credential access — same posture as policy/evaluate.ts and
 * risk/score.ts. This is reachability analysis over CURRENT policy, not
 * history: it is not audit evidence and keeps no record of past exposure.
 */
import type { CompiledGrant, CompiledPolicy } from "../policy/compile.ts";
import { actionVocabulary } from "../adapters/vocabulary.ts";

export type Severity = "low" | "elevated" | "high";

export interface BroadGrant {
  readonly pattern: string;
  readonly matches: readonly string[];
}

export interface UpstreamExposure {
  readonly upstream: string;
  readonly type: string;
  readonly enumerable: boolean;
  readonly autoAllow: readonly string[];
  readonly requiresApproval: readonly string[];
  readonly broadGrants: readonly BroadGrant[];
  readonly rawPatterns?: {
    readonly allow: readonly string[];
    readonly requireApproval: readonly string[];
    readonly deny: readonly string[];
  };
}

export interface DelegationExposure {
  readonly id: string;
  readonly note: string;
  readonly actions: readonly string[];
  readonly expiresInSeconds: number;
}

export interface BlastRadiusReport {
  readonly agent: string;
  readonly upstreams: readonly UpstreamExposure[];
  readonly delegations: readonly DelegationExposure[];
  readonly severity: Severity;
  readonly reasons: readonly string[];
}

/** The parts of a live Delegation record the analyzer needs. */
export interface DelegationLike {
  readonly id: string;
  readonly parentAgentId: string;
  readonly note: string;
  readonly actions: readonly string[];
  readonly expiresAt: number; // epoch ms
}

export interface BlastRadiusInput {
  readonly agent: string;
  readonly upstreams: Readonly<Record<string, { readonly type: string }>>;
  readonly policy: CompiledPolicy;
  /** ALL live delegations (not pre-filtered) — filtered here by `agent`. */
  readonly delegations: readonly DelegationLike[];
  readonly now: number; // epoch ms
}

const BROAD_GRANT_MIN_MATCHES = 3;
const DESTRUCTIVE_RE = /delete|merge|:write$/;

function isDestructive(action: string): boolean {
  return DESTRUCTIVE_RE.test(action);
}

type ActionDecision = "deny" | "require_approval" | "allow" | "blocked";

/**
 * Evaluate one vocabulary action against a grant. Mirrors policy/evaluate.ts's
 * precedence (deny > require_approval > allow > blocked) but over an
 * enumerated vocabulary instead of a single incoming action.
 */
function evaluateAction(
  grant: CompiledGrant | undefined,
  action: string,
): { decision: ActionDecision; pattern: string | null } {
  if (!grant) return { decision: "blocked", pattern: null };
  // Reachability semantics (mirrors evaluate()'s null-target mode): a
  // target-scoped deny is evadable via some other target, so it cannot make
  // an action unreachable; a scoped allow/approval IS reachable via some
  // target, so it counts as exposure.
  const deny = grant.deny.find((r) => r.targets === null && r.action.re.test(action));
  if (deny) return { decision: "deny", pattern: deny.action.source };
  const approval = grant.requireApproval.find((r) => r.action.re.test(action));
  if (approval) return { decision: "require_approval", pattern: approval.action.source };
  const allow = grant.allow.find((r) => r.action.re.test(action));
  if (allow) return { decision: "allow", pattern: allow.action.source };
  return { decision: "blocked", pattern: null };
}

function analyzeUpstream(upstream: string, type: string, grant: CompiledGrant | undefined): UpstreamExposure {
  const vocabulary = actionVocabulary(type);
  if (vocabulary === null) {
    return {
      upstream,
      type,
      enumerable: false,
      autoAllow: [],
      requiresApproval: [],
      broadGrants: [],
      rawPatterns: {
        allow: (grant?.allow ?? []).map((r) => r.action.source),
        requireApproval: (grant?.requireApproval ?? []).map((r) => r.action.source),
        deny: (grant?.deny ?? []).map((r) => r.action.source),
      },
    };
  }

  const autoAllow: string[] = [];
  const requiresApproval: string[] = [];
  const byPattern = new Map<string, string[]>();

  for (const action of vocabulary) {
    const { decision, pattern } = evaluateAction(grant, action);
    if (decision === "allow") autoAllow.push(action);
    else if (decision === "require_approval") requiresApproval.push(action);
    if ((decision === "allow" || decision === "require_approval") && pattern) {
      const list = byPattern.get(pattern) ?? [];
      list.push(action);
      byPattern.set(pattern, list);
    }
  }

  const broadGrants: BroadGrant[] = [...byPattern.entries()]
    .filter(([, matches]) => matches.length >= BROAD_GRANT_MIN_MATCHES)
    .map(([pattern, matches]) => ({ pattern, matches: matches.slice().sort() }));

  return {
    upstream,
    type,
    enumerable: true,
    autoAllow: autoAllow.slice().sort(),
    requiresApproval: requiresApproval.slice().sort(),
    broadGrants,
  };
}

export function analyzeBlastRadius(input: BlastRadiusInput): BlastRadiusReport {
  const upstreams: UpstreamExposure[] = Object.entries(input.upstreams)
    .map(([name, cfg]) => analyzeUpstream(name, cfg.type, input.policy.grants.get(name)))
    .sort((a, b) => a.upstream.localeCompare(b.upstream));

  const delegations: DelegationExposure[] = input.delegations
    .filter((d) => d.parentAgentId === input.agent && d.expiresAt > input.now)
    .map((d) => ({
      id: d.id,
      note: d.note,
      actions: d.actions,
      expiresInSeconds: Math.max(0, Math.round((d.expiresAt - input.now) / 1000)),
    }))
    .sort((a, b) => b.expiresInSeconds - a.expiresInSeconds);

  const reasons: string[] = [];
  let score = 0;
  for (const u of upstreams) {
    const destructiveAllow = u.autoAllow.filter(isDestructive);
    if (destructiveAllow.length > 0) {
      score += destructiveAllow.length * 15;
      reasons.push(`${u.upstream}: auto-allows ${destructiveAllow.join(", ")}`);
    }
    for (const bg of u.broadGrants) {
      if (bg.matches.some(isDestructive)) {
        score += 25;
        reasons.push(`${u.upstream}: broad grant "${bg.pattern}" reaches ${bg.matches.join(", ")}`);
      }
    }
  }
  score = Math.min(score, 100);
  const severity: Severity = score >= 50 ? "high" : score >= 20 ? "elevated" : "low";

  return { agent: input.agent, upstreams, delegations, severity, reasons };
}
