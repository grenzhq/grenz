/**
 * Policy linter — static authoring-quality checks over a compiled policy.
 *
 * Pure and synchronous, same posture as policy/evaluate.ts. Only runs against
 * upstream types with a known, enumerable action vocabulary (github/linear/
 * slack) — the generic `mcp` type accepts arbitrary tool names and is skipped
 * entirely rather than approximated. Findings are advisory (authoring quality,
 * not policy validity): a policy with a dead or shadowed pattern is still a
 * well-formed, safely deny-by-default policy.
 */
import type { CompiledGrant, CompiledRule, CompiledPolicy, CompiledPattern } from "./compile.ts";
import { actionVocabulary } from "../adapters/vocabulary.ts";

export type LintKind = "dead_pattern" | "shadowed_pattern" | "broad_grant";
export type LintClause = "allow" | "deny" | "require_approval";

export interface LintFinding {
  readonly tool: string;
  readonly clause: LintClause;
  readonly pattern: string;
  readonly kind: LintKind;
  readonly detail: string;
}

const BROAD_GRANT_MIN_MATCHES = 3;

function matchedActions(re: RegExp, vocabulary: readonly string[]): string[] {
  return vocabulary.filter((a) => re.test(a));
}

function lintClause(
  tool: string,
  clause: LintClause,
  rules: readonly CompiledRule[],
  vocabulary: readonly string[],
  checkBroad: boolean,
  findings: LintFinding[],
): void {
  const matchSets = rules.map((r) => matchedActions(r.action.re, vocabulary));
  for (let i = 0; i < rules.length; i++) {
    const pattern = rules[i]!.action;
    const matches = matchSets[i]!;

    if (matches.length === 0) {
      findings.push({
        tool,
        clause,
        pattern: pattern.source,
        kind: "dead_pattern",
        detail: "matches no known action for this upstream type (possible typo)",
      });
      // A dead pattern matches nothing, so checking whether it's "shadowed" would
      // vacuously succeed against any earlier pattern (every element of an empty
      // set trivially satisfies "covered by"). Skip the rest of this pattern's
      // checks to avoid a spurious shadowed_pattern finding on top of dead_pattern.
      continue;
    }

    for (let j = 0; j < i; j++) {
      // A target-scoped earlier rule can miss on target and fall through, so
      // it cannot shadow a later rule.
      if (rules[j]!.targets !== null) continue;
      const earlier = matchSets[j]!;
      if (matches.every((a) => earlier.includes(a))) {
        findings.push({
          tool,
          clause,
          pattern: pattern.source,
          kind: "shadowed_pattern",
          detail: `already fully covered by earlier pattern "${rules[j]!.action.source}" in the same ${clause} list`,
        });
        break;
      }
    }

    if (checkBroad && matches.length >= BROAD_GRANT_MIN_MATCHES) {
      findings.push({
        tool,
        clause,
        pattern: pattern.source,
        kind: "broad_grant",
        detail: `reaches ${matches.length} actions: ${matches.slice().sort().join(", ")}`,
      });
    }
  }
}

export type WeightLintKind = "unreachable_weight" | "dominated_weight" | "cross_tool_weight";

export interface WeightLintFinding {
  readonly pattern: string;
  readonly kind: WeightLintKind;
  readonly detail: string;
}

/**
 * Lint `budget.weights` for the three cost footguns. Advisory, like `lintPolicy`,
 * and only reasons over granted tools with an enumerable action vocabulary (a
 * weight targeting generic `mcp` actions can't be checked and is left alone).
 *
 * - `unreachable_weight`: a cost greater than an applicable ceiling means the
 *   action can never forward — the language for "never" is `deny`, not an
 *   infinite cost.
 * - `dominated_weight`: under max-wins, a cheaper entry whose matched actions are
 *   all priced at least as high by another entry is dead (the classic broken
 *   downward carve-out, e.g. `repo:*: 10` + `repo:read: 1`).
 * - `cross_tool_weight`: action names aren't tool-qualified, so one global glob
 *   can tax more than one tool's vocabulary (e.g. `issue:*` on GitHub + Linear).
 */
export function lintWeights(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly type: string }>>,
): readonly WeightLintFinding[] {
  const findings: WeightLintFinding[] = [];
  if (policy.budgetWeights.length === 0) return findings;

  // Granted tools whose vocabulary is enumerable, tagged by tool name.
  const tools: { readonly tool: string; readonly vocabulary: readonly string[] }[] = [];
  for (const [tool] of policy.grants) {
    const upstream = upstreams[tool];
    if (!upstream) continue;
    const vocabulary = actionVocabulary(upstream.type);
    if (vocabulary === null) continue;
    tools.push({ tool, vocabulary });
  }

  // Per weight entry, the (tool, action) pairs it matches across those vocabularies.
  const matchesFor = policy.budgetWeights.map((w) => {
    const hits: { readonly tool: string; readonly action: string }[] = [];
    for (const t of tools) {
      for (const a of t.vocabulary) if (w.pattern.re.test(a)) hits.push({ tool: t.tool, action: a });
    }
    return hits;
  });

  for (let i = 0; i < policy.budgetWeights.length; i++) {
    const w = policy.budgetWeights[i]!;
    const hits = matchesFor[i]!;
    const src = w.pattern.source;
    const toolsHit = [...new Set(hits.map((h) => h.tool))].sort();

    // cross_tool_weight — a specific glob bleeding across tools (`*` is an
    // intentional global cost, not a bleed, so it is exempt).
    if (src !== "*" && toolsHit.length > 1) {
      findings.push({
        pattern: src,
        kind: "cross_tool_weight",
        detail: `taxes actions in ${toolsHit.join(" + ")} — action names aren't tool-qualified`,
      });
    }

    // unreachable_weight — cost strictly above an applicable ceiling for a tool
    // it matches. From an empty window the first attempt already exceeds it.
    let flaggedUnreachable = false;
    for (const t of toolsHit) {
      const ceilings: { readonly name: string; readonly limit: number }[] = [];
      if (policy.maxActionsPerHour !== null) {
        ceilings.push({ name: "max_actions_per_hour", limit: policy.maxActionsPerHour });
      }
      const up = policy.perUpstreamActionsPerHour.get(t);
      if (up !== undefined) ceilings.push({ name: `per_upstream.${t}`, limit: up });
      const tightest = ceilings.filter((c) => w.weight > c.limit).sort((a, b) => a.limit - b.limit)[0];
      if (tightest) {
        findings.push({
          pattern: src,
          kind: "unreachable_weight",
          detail: `cost ${w.weight} exceeds ${tightest.name} (${tightest.limit}); this action can never forward — use \`deny\` to forbid it`,
        });
        flaggedUnreachable = true;
        break;
      }
    }

    // dominated_weight — another entry prices every action this one matches at
    // least as high (max-wins makes this entry dead). Strictly-higher from any
    // position, or equal from an earlier position (so one of an equal pair stays).
    if (!flaggedUnreachable && hits.length > 0) {
      for (let j = 0; j < policy.budgetWeights.length; j++) {
        if (j === i) continue;
        const other = policy.budgetWeights[j]!;
        const dominates = other.weight > w.weight || (other.weight === w.weight && j < i);
        if (!dominates) continue;
        const otherHits = matchesFor[j]!;
        const covered = hits.every((h) => otherHits.some((e) => e.tool === h.tool && e.action === h.action));
        if (covered) {
          findings.push({
            pattern: src,
            kind: "dominated_weight",
            detail: `every action it matches is already priced ≥${w.weight} by "${other.pattern.source}" (max-wins makes this entry dead)`,
          });
          break;
        }
      }
    }
  }
  return findings;
}

export interface FlowLintFinding {
  readonly side: "when" | "then";
  readonly pattern: string;
  readonly detail: string;
}

/**
 * Lint taint-flow rules. A `when`/`then` glob that matches no known action in
 * any granted, enumerable-vocabulary tool is almost certainly a typo — and a
 * silent one: a dead `then` means the sink is never gated, a dead `when` means
 * the flow never taints. Advisory, like the other linters; only reasons over
 * tools whose vocabulary is enumerable.
 */
export function lintFlows(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly type: string }>>,
): readonly FlowLintFinding[] {
  const findings: FlowLintFinding[] = [];
  if (policy.flows.length === 0) return findings;

  const vocab: string[] = [];
  for (const [tool] of policy.grants) {
    const upstream = upstreams[tool];
    if (!upstream) continue;
    const vocabulary = actionVocabulary(upstream.type);
    if (vocabulary === null) continue;
    vocab.push(...vocabulary);
  }
  if (vocab.length === 0) return findings; // nothing enumerable to check against

  const dead = (p: CompiledPattern): boolean => !vocab.some((a) => p.re.test(a));
  for (const flow of policy.flows) {
    for (const p of flow.when) {
      if (dead(p)) {
        findings.push({
          side: "when",
          pattern: p.source,
          detail: "matches no known action for any granted tool (possible typo — the flow never taints)",
        });
      }
    }
    for (const p of flow.then) {
      if (dead(p)) {
        findings.push({
          side: "then",
          pattern: p.source,
          detail: "matches no known action for any granted tool (possible typo — the sink is never gated)",
        });
      }
    }
  }
  return findings;
}

export interface TripwireLintFinding {
  readonly pattern: string;
  readonly detail: string;
}

/**
 * Lint tripwires for the self-revoke footgun: a tripwire whose action overlaps
 * an `allow` rule means the agent trips the kill-switch on normal, permitted
 * work. Advisory; only reasons over granted tools with an enumerable vocabulary.
 */
export function lintTripwires(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly type: string }>>,
): readonly TripwireLintFinding[] {
  const findings: TripwireLintFinding[] = [];
  if (policy.tripwires.length === 0) return findings;
  for (const [tool, grant] of policy.grants) {
    const upstream = upstreams[tool];
    if (!upstream) continue;
    const vocabulary = actionVocabulary(upstream.type);
    if (vocabulary === null) continue;
    for (const wire of policy.tripwires) {
      const overlap = vocabulary.find(
        (a) => wire.action.re.test(a) && grant.allow.some((r) => r.action.re.test(a)),
      );
      if (overlap !== undefined) {
        findings.push({
          pattern: wire.action.source,
          detail: `also matches an allowed action (${tool}:${overlap}) — the agent self-revokes on normal work`,
        });
      }
    }
  }
  return findings;
}

export interface DecoyLintFinding {
  readonly pattern: string;
  readonly detail: string;
}

/**
 * Flag any grant whose tool key names a decoy upstream. No legitimate policy
 * grants a decoy — a touch is a trip — so such a grant is a typo or an
 * attacker-authored policy. Advisory: the hard gate at dispatch is the
 * enforcement. The policy engine stays decoy-unaware; this is the only bridge.
 */
export function lintDecoys(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly decoy?: boolean }>>,
): readonly DecoyLintFinding[] {
  const findings: DecoyLintFinding[] = [];
  for (const [tool] of policy.grants) {
    if (upstreams[tool]?.decoy === true) {
      findings.push({
        pattern: tool,
        detail: `grant for '${tool}' targets a decoy upstream — no legitimate policy grants a decoy; this is a typo or an attacker-authored policy`,
      });
    }
  }
  return findings;
}

export interface PinLintFinding {
  readonly ruleIndex: number;
  readonly pattern: string;
  readonly detail: string;
}

/**
 * Lint session pin rules. An `on` glob that matches no known action for any
 * granted, enumerable-vocabulary tool is almost certainly a typo — and a silent
 * one: the pin never establishes or constrains anything. Advisory, like the
 * other linters; only reasons over tools whose vocabulary is enumerable.
 */
export function lintPins(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly type: string }>>,
): readonly PinLintFinding[] {
  const findings: PinLintFinding[] = [];
  if (policy.pins.length === 0) return findings;

  const vocab: string[] = [];
  for (const [tool] of policy.grants) {
    const upstream = upstreams[tool];
    if (!upstream) continue;
    const vocabulary = actionVocabulary(upstream.type);
    if (vocabulary === null) continue;
    vocab.push(...vocabulary);
  }
  if (vocab.length === 0) return findings; // nothing enumerable to check against

  for (let i = 0; i < policy.pins.length; i++) {
    for (const p of policy.pins[i]!.on) {
      if (!vocab.some((a) => p.re.test(a))) {
        findings.push({
          ruleIndex: i,
          pattern: p.source,
          detail: "matches no known action for any granted tool (possible typo — the pin never engages)",
        });
      }
    }
  }
  return findings;
}

export interface ResponseLintFinding {
  readonly ruleIndex: number;
  readonly pattern: string;
  readonly detail: string;
}

/**
 * Lint response-size caps. An `on` glob that matches no known action for any
 * granted, enumerable-vocabulary tool is almost certainly a typo — and a silent
 * one: the cap never applies to anything. Advisory, like the other linters.
 */
export function lintResponses(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly type: string }>>,
): readonly ResponseLintFinding[] {
  const findings: ResponseLintFinding[] = [];
  if (policy.responses.length === 0) return findings;

  const vocab: string[] = [];
  for (const [tool] of policy.grants) {
    const upstream = upstreams[tool];
    if (!upstream) continue;
    const vocabulary = actionVocabulary(upstream.type);
    if (vocabulary === null) continue;
    vocab.push(...vocabulary);
  }
  if (vocab.length === 0) return findings; // nothing enumerable to check against

  for (let i = 0; i < policy.responses.length; i++) {
    for (const p of policy.responses[i]!.on) {
      if (!vocab.some((a) => p.re.test(a))) {
        findings.push({
          ruleIndex: i,
          pattern: p.source,
          detail: "matches no known action for any granted tool (possible typo — the cap never applies)",
        });
      }
    }
  }
  return findings;
}

export type PerAgentMap = "budget.per_agent" | "approvals.per_agent";

export interface PerAgentKeyLintFinding {
  readonly map: PerAgentMap;
  readonly agentId: string;
  /** Closest registered id when the key looks like a typo, else null. */
  readonly suggestion: string | null;
  readonly detail: string;
}

/** Levenshtein edit distance, capped-free (ids are short). Pure. */
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  let curr = new Array<number>(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n]!;
}

/**
 * Closest registered id to `id`, but only when it is close enough to plausibly
 * be a typo (edit distance within `max(2, floor(shorter/4))`). Returns null when
 * nothing is near — a wholly-unrelated key is a stale/removed agent, not a slip.
 */
function nearestId(id: string, candidates: readonly string[]): string | null {
  let best: string | null = null;
  let bestDist = Infinity;
  for (const c of candidates) {
    const d = editDistance(id, c);
    if (d < bestDist) {
      bestDist = d;
      best = c;
    }
  }
  if (best === null) return null;
  const threshold = Math.max(2, Math.floor(Math.min(id.length, best.length) / 4));
  return bestDist <= threshold ? best : null;
}

/**
 * Lint the per-agent policy maps for the silent-dead-key footgun: a
 * `budget.per_agent` ceiling or `approvals.per_agent` overlay is keyed by a bare
 * agent-id string that is NEVER cross-checked against the agent registry. A typo
 * ("claude-code-prd"), or a renamed/removed agent, leaves the override keyed to
 * an id that no token ever resolves to — so the ceiling never caps and the
 * approval overlay never gates, silently, with nothing to warn the author.
 *
 * Advisory, like the rest of this file: a dead key fails toward *less* friction
 * on a policy that still denies-by-default (the overlay never OPENS anything it
 * had closed), exactly like a dead taint-flow `then`. The check is local to this
 * proxy's registry — a shared policy distributed to many proxies will correctly
 * read a key meant for another proxy as "inert here", which is true of this
 * deployment. `registeredAgentIds` is the set of `agents[].id` from grenz.yaml.
 */
export function lintPerAgentKeys(
  policy: CompiledPolicy,
  registeredAgentIds: readonly string[],
): readonly PerAgentKeyLintFinding[] {
  const findings: PerAgentKeyLintFinding[] = [];
  const registered = new Set(registeredAgentIds);

  const check = (keys: Iterable<string>, map: PerAgentMap, human: string): void => {
    for (const id of keys) {
      if (registered.has(id)) continue;
      const suggestion = nearestId(id, registeredAgentIds);
      const hint = suggestion === null ? "" : ` (did you mean "${suggestion}"?)`;
      findings.push({
        map,
        agentId: id,
        suggestion,
        detail: `names no agent registered on this proxy — the ${human} for "${id}" is inert here${hint}`,
      });
    }
  };

  check(policy.perAgentActionsPerHour.keys(), "budget.per_agent", "per-agent budget ceiling");
  check(policy.perAgentApproval.keys(), "approvals.per_agent", "per-agent approval overlay");
  return findings;
}

export function lintPolicy(
  policy: CompiledPolicy,
  upstreams: Readonly<Record<string, { readonly type: string }>>,
): readonly LintFinding[] {
  const findings: LintFinding[] = [];
  for (const [tool, grant] of policy.grants) {
    const upstream = upstreams[tool];
    if (!upstream) continue;
    const vocabulary = actionVocabulary(upstream.type);
    if (vocabulary === null) continue; // not enumerable (generic mcp, or unknown type) — skip

    const g: CompiledGrant = grant;
    lintClause(tool, "deny", g.deny, vocabulary, false, findings);
    lintClause(tool, "require_approval", g.requireApproval, vocabulary, true, findings);
    lintClause(tool, "allow", g.allow, vocabulary, true, findings);
  }
  return findings;
}

/**
 * Exec-grant lint: the two ways a `bash` grant reads safer than it is.
 *
 * Runs independently of `upstreams`. Every other linter here keys off an
 * upstream's action vocabulary and skips a tool with no upstream entry — and
 * `bash` has no upstream, because there is nothing to forward to. Wiring these
 * checks into `lintPolicy` would therefore have silently skipped them.
 */
export type ExecLintKind =
  | "exec_deny_order_evadable"
  | "exec_allow_unscoped"
  | "exec_allow_execution_equivalent";

export interface ExecLintFinding {
  readonly clause: LintClause;
  readonly pattern: string;
  readonly kind: ExecLintKind;
  readonly detail: string;
}

/** The tool whose targets are folded command lines. */
const EXEC_TOOL = "bash";

/**
 * Binaries for which `exec:<binary>` is, in practice, arbitrary code execution.
 *
 * A target glob confines the COMMAND LINE. It says nothing about what the
 * program on that command line then runs, and for everything below the answer is
 * "whatever it was handed": an interpreter runs its script, `make` runs its
 * recipe, `npm` runs its package scripts, `git` runs its hooks, `ssh` runs the
 * remote side.
 *
 * That was always true — `python3 build.py` has never been confinable in any
 * stronger sense. It only became worth saying out loud once Grenz stopped
 * refusing `python3 <<'PY'`, which had been concealing the fact for one idiom
 * while leaving every other one open.
 */
const EXECUTION_EQUIVALENT: ReadonlySet<string> = new Set([
  // Shells. These never reach the engine (the adapter refuses them), but a
  // grant naming one still reflects a misunderstanding worth correcting.
  "sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "csh", "tcsh",
  // Language runtimes.
  "python", "python2", "python3", "node", "deno", "bun", "perl", "ruby", "php",
  "lua", "awk", "gawk", "mawk", "Rscript", "osascript", "java", "scala",
  // Build and package tooling that runs project-authored scripts.
  "make", "cmake", "ninja", "npm", "npx", "pnpm", "yarn", "cargo", "go",
  "gradle", "mvn", "rake", "just", "task",
  // Runs repository hooks.
  "git",
  // Runs something somewhere else, or as someone else.
  "ssh", "docker", "podman", "kubectl", "sudo", "doas", "env", "chroot", "xargs",
]);

/** True for an action pattern that can match an `exec:` action. */
function touchesExec(source: string): boolean {
  return source.startsWith("exec:") || source === "*" || source.startsWith("exec");
}

/** A target pattern that constrains nothing. */
function isUnscopedTarget(targets: readonly CompiledPattern[] | null): boolean {
  if (targets === null) return true; // bare-string rule — any target
  return targets.length === 0 || targets.some((t) => t.source === "*");
}

export function lintExec(policy: CompiledPolicy): readonly ExecLintFinding[] {
  const grant = policy.grants.get(EXEC_TOOL);
  if (!grant) return [];
  const findings: ExecLintFinding[] = [];

  // 1. A deny on an exec target is ORDER-EVADABLE.
  //
  // The target is the folded command line with argv space-joined, so argument
  // ORDER is significant and a deny glob is positional:
  //
  //     allow: curl *
  //     deny:  curl * evil.com *
  //
  // `curl evil.com -X POST` does not match the deny, does match the allow, and
  // is permitted. Normalizing argv order would need per-binary flag semantics —
  // that is the structured-target work, not something a linter can paper over.
  // So the finding says what actually works: confine with narrow allows.
  for (const rule of grant.deny) {
    if (!touchesExec(rule.action.source)) continue;
    if (rule.targets === null) continue; // an unscoped deny is absolute — not evadable
    findings.push({
      clause: "deny",
      pattern: rule.action.source,
      kind: "exec_deny_order_evadable",
      detail:
        "bash targets are the folded command line, so argument ORDER matters and this deny " +
        "can be bypassed by reordering arguments — confine with narrow `allow` targets instead " +
        "of a broad allow plus this deny",
    });
  }

  // 2. An unscoped exec allow reads far safer than it is.
  //
  // `allow exec:git` looks like "git is allowed", but the action is only the
  // BASENAME — all real confinement lives in the target, and with no target
  // `/tmp/evil/git` passes too.
  //
  // Advisory, in the spirit of this file: a deliberately broad grant on a
  // read-only binary (`exec:ls`) is a legitimate policy and will also be
  // flagged. That is the accepted false-positive cost of naming the footgun.
  for (const rule of grant.allow) {
    if (!rule.action.source.startsWith("exec:")) continue;
    if (!isUnscopedTarget(rule.targets)) continue;
    findings.push({
      clause: "allow",
      pattern: rule.action.source,
      kind: "exec_allow_unscoped",
      detail:
        "matches ANY argv and any path to that binary (the action is only the basename, so " +
        "`/tmp/evil/...` passes too) — add `targets:` anchored to the paths and arguments you mean",
    });
  }

  // 3. `exec:python3` IS arbitrary code execution, and a target does not change
  //    that. Fires regardless of how narrow the target is, because the target
  //    constrains the command line and the concern is one level below it.
  for (const rule of grant.allow) {
    const source = rule.action.source;
    if (!source.startsWith("exec:")) continue;
    const binary = source.slice("exec:".length);
    if (!EXECUTION_EQUIVALENT.has(binary)) continue;
    findings.push({
      clause: "allow",
      pattern: source,
      kind: "exec_allow_execution_equivalent",
      detail:
        `\`${source}\` permits arbitrary code execution. Target globs constrain the command ` +
        "line, not what the interpreter then runs. Grant this only where that is acceptable",
    });
  }

  return findings;
}
