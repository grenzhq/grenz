/**
 * Pure, time-aware policy tightening: propose demoting or dropping `allow`
 * grants an agent has not exercised within a staleness threshold. Decay is
 * shrinkwrap's time-aware sibling — it reads the same explicit_allow evidence,
 * adds a per-action last-used timestamp and a log-coverage gate, and rewrites
 * ONLY the `allow` lists. Every other field (deny, require_approval, targets,
 * budgets, flows, pins) is preserved untouched. It only ever tightens.
 *
 * SAFETY — the request log is plain and freely truncatable (operational
 * visibility only). The ABSENCE of usage rows is therefore NO evidence of
 * non-use: a missing action is classified NO_EVIDENCE and always KEPT, never
 * decayed. The coverage gate makes "stale"/"unused" impossible to conclude
 * unless the log has been observing since before the staleness horizon. This is
 * what lets the log stay plain and truncatable — truncation costs decay
 * confidence, never safety. Nothing here runs on a decision path; it produces a
 * candidate policy a human reviews, diffs, signs, and distributes.
 */
import type { PolicySource, GrantSource } from "./schema.ts";
import { compileGlob } from "./glob.ts";

export type ActionClass = "active" | "stale" | "unused" | "no_evidence";
export type DecayMode = "demote" | "drop";

/** A source `allow`/`require_approval` rule: a bare action string or an object. */
type RuleSource = GrantSource["allow"][number];

/** Per-agent usage evidence extracted from the request log (operational only). */
export interface DecayEvidence {
  /** Per (tool, action) last explicit_allow use + row count. Missing key = no row. */
  readonly lastUsed: ReadonlyMap<string, { readonly lastTs: number; readonly n: number }>;
  /** Earliest row in the WHOLE log, or null (empty / fully truncated). */
  readonly coverageStart: number | null;
  /** Total explicit_allow rows for THIS agent; 0 triggers the zero-usage refusal. */
  readonly agentUsageRows: number;
}

export interface DecayOptions {
  readonly now: number;
  readonly staleDays: number;
  readonly mode: DecayMode;
  /** The agent this run analyzes — the one whose evidence was queried. Names the
   *  refusal message and the report header, so a `--agent` override that finds no
   *  usage points at the id the operator actually typed, not the policy default. */
  readonly agentId: string;
}

/** Evidence-map key for a (tool, action) pair. Tool and action identifiers never
 *  contain a space, so a space separator is unambiguous (and readable in a dump). */
export function evidenceKey(tool: string, action: string): string {
  return `${tool} ${action}`;
}

export interface DecayActionInfo {
  readonly tool: string;
  readonly action: string;
  readonly cls: ActionClass;
  readonly lastTs: number | null;
  readonly n: number;
}

export type RuleDisposition = "kept" | "partial" | "decayed" | "dead" | "mcp_skipped";

export interface DecayRuleChange {
  readonly tool: string;
  readonly pattern: string;
  readonly disposition: RuleDisposition;
  readonly keptActions: readonly string[];
  readonly decayedActions: readonly string[];
}

export interface DecayReport {
  readonly agent: string;
  readonly now: number;
  readonly coverageStart: number | null;
  readonly covered: boolean;
  readonly staleDays: number;
  readonly mode: DecayMode;
  readonly actions: readonly DecayActionInfo[];
  readonly changes: readonly DecayRuleChange[];
  readonly demotedCount: number;
  readonly droppedCount: number;
  readonly activePairs: readonly { readonly tool: string; readonly action: string }[];
}

export type DecayResult =
  | { readonly ok: false; readonly reason: string }
  | { readonly ok: true; readonly source: PolicySource; readonly report: DecayReport };

/** CLI-derived fleet context for the report (never affects classification). */
export interface FleetContext {
  /** Proxy labels (or file paths) that contributed evidence. */
  readonly files: readonly string[];
  /** evidenceKey()s that are ACTIVE only because a peer supplied a fresh lastTs. */
  readonly vetoedKeys: ReadonlySet<string>;
}

/** Emit a literal-action rule preserving the source rule's targets + message. */
function literalRule(action: string, from: RuleSource): RuleSource {
  if (typeof from === "string") return action;
  const out: { action: string; targets?: string[]; message?: string } = { action };
  if (from.targets && from.targets.length > 0) out.targets = [...from.targets];
  if (from.message) out.message = from.message;
  return out;
}

/** Structural equality for deduping a demoted rule against existing require_approval. */
function sameRule(a: RuleSource, b: RuleSource): boolean {
  const na =
    typeof a === "string"
      ? { action: a, targets: undefined as readonly string[] | undefined, message: undefined as string | undefined }
      : { action: a.action, targets: a.targets, message: a.message };
  const nb =
    typeof b === "string"
      ? { action: b, targets: undefined as readonly string[] | undefined, message: undefined as string | undefined }
      : { action: b.action, targets: b.targets, message: b.message };
  if (na.action !== nb.action || na.message !== nb.message) return false;
  const ta = na.targets ?? null;
  const tb = nb.targets ?? null;
  if ((ta === null) !== (tb === null)) return false;
  if (ta && tb) {
    if (ta.length !== tb.length) return false;
    for (let i = 0; i < ta.length; i++) if (ta[i] !== tb[i]) return false;
  }
  return true;
}

function classify(lastTs: number | null, covered: boolean, staleBefore: number): ActionClass {
  if (lastTs !== null && lastTs >= staleBefore) return "active";
  if (!covered) return "no_evidence";
  return lastTs === null ? "unused" : "stale";
}

export function decayPolicy(
  source: PolicySource,
  vocabularies: ReadonlyMap<string, readonly string[] | null>,
  evidence: DecayEvidence,
  options: DecayOptions,
): DecayResult {
  if (evidence.agentUsageRows === 0) {
    return { ok: false, reason: `no usage recorded for agent ${options.agentId} — check --agent` };
  }

  const staleBefore = options.now - options.staleDays * 86_400_000;
  const covered = evidence.coverageStart !== null && evidence.coverageStart <= staleBefore;

  const actions: DecayActionInfo[] = [];
  const changes: DecayRuleChange[] = [];
  const activePairs: { tool: string; action: string }[] = [];
  let demotedCount = 0;
  let droppedCount = 0;

  const grants: GrantSource[] = source.grants.map((grant) => {
    const vocabulary = vocabularies.get(grant.tool) ?? null;
    const newAllow: RuleSource[] = [];
    const demoted: RuleSource[] = [];

    for (const rule of grant.allow) {
      const pattern = typeof rule === "string" ? rule : rule.action;

      if (vocabulary === null) {
        newAllow.push(rule);
        changes.push({ tool: grant.tool, pattern, disposition: "mcp_skipped", keptActions: [], decayedActions: [] });
        continue;
      }

      const re = compileGlob(pattern);
      const reachable = vocabulary.filter((a) => re.test(a));
      if (reachable.length === 0) {
        newAllow.push(rule);
        changes.push({ tool: grant.tool, pattern, disposition: "dead", keptActions: [], decayedActions: [] });
        continue;
      }

      const kept: string[] = [];
      const decayed: string[] = [];
      for (const a of reachable) {
        const ev = evidence.lastUsed.get(evidenceKey(grant.tool, a)) ?? null;
        const lastTs = ev ? ev.lastTs : null;
        const cls = classify(lastTs, covered, staleBefore);
        actions.push({ tool: grant.tool, action: a, cls, lastTs, n: ev ? ev.n : 0 });
        if (cls === "active") activePairs.push({ tool: grant.tool, action: a });
        if (cls === "active" || cls === "no_evidence") kept.push(a);
        else decayed.push(a);
      }

      if (decayed.length === 0) {
        newAllow.push(rule);
        changes.push({ tool: grant.tool, pattern, disposition: "kept", keptActions: kept, decayedActions: [] });
      } else if (kept.length === 0) {
        if (options.mode === "demote") {
          demoted.push(rule);
          demotedCount += 1;
        } else {
          droppedCount += 1;
        }
        changes.push({ tool: grant.tool, pattern, disposition: "decayed", keptActions: [], decayedActions: decayed });
      } else {
        for (const a of kept) newAllow.push(literalRule(a, rule));
        if (options.mode === "demote") {
          for (const a of decayed) {
            demoted.push(literalRule(a, rule));
            demotedCount += 1;
          }
        } else {
          droppedCount += decayed.length;
        }
        changes.push({ tool: grant.tool, pattern, disposition: "partial", keptActions: kept, decayedActions: decayed });
      }
    }

    const requireApproval: RuleSource[] = [...grant.require_approval];
    for (const d of demoted) {
      if (!requireApproval.some((r) => sameRule(r, d))) requireApproval.push(d);
    }

    return { ...grant, allow: newAllow, require_approval: requireApproval };
  });

  const report: DecayReport = {
    agent: options.agentId,
    now: options.now,
    coverageStart: evidence.coverageStart,
    covered,
    staleDays: options.staleDays,
    mode: options.mode,
    actions,
    changes,
    demotedCount,
    droppedCount,
    activePairs,
  };

  return { ok: true, source: { ...source, grants }, report };
}

function fmtDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * Pure human report for `grenz policy decay` → stderr. `verified` is asserted by
 * the CALLER (the differential verify lives in the CLI, not here): pass true only
 * after that check passes, so the "✓ verified" line is never a claim this pure
 * function cannot substantiate.
 */
export function formatDecayReport(report: DecayReport, verified = false, fleet?: FleetContext): string {
  const lines: string[] = [`decay — agent ${report.agent}, stale threshold ${report.staleDays}d`];

  if (report.coverageStart === null) {
    lines.push("  log coverage: none (empty or fully truncated log)");
  } else {
    const ageDays = Math.floor((report.now - report.coverageStart) / 86_400_000);
    const suff = report.covered ? `sufficient (>= ${report.staleDays}d)` : `INSUFFICIENT (< ${report.staleDays}d)`;
    lines.push(`  log coverage: ${fmtDate(report.coverageStart)} → now (${ageDays}d) — ${suff}`);
    if (!report.covered) {
      lines.push("  log younger than the staleness threshold; proposal unchanged from active policy");
    }
  }
  if (fleet && fleet.files.length > 0) {
    const vetoed = report.actions.filter(
      (a) => a.cls === "active" && fleet.vetoedKeys.has(evidenceKey(a.tool, a.action)),
    ).length;
    lines.push(
      `  fleet evidence: ${fleet.files.length} file(s) merged (${fleet.files.join(", ")}) — ` +
        `${vetoed} action(s) kept that are idle here but used on a peer`,
    );
    lines.push("  (unlisted proxies are still unrepresented — this is not the whole fleet)");
  } else {
    lines.push("  evidence is from THIS proxy's log only (merge peers with --evidence)");
  }

  const decayVerb = report.mode === "demote" ? "demote" : "drop";
  const byTool = new Map<string, DecayActionInfo[]>();
  for (const a of report.actions) {
    let arr = byTool.get(a.tool);
    if (!arr) {
      arr = [];
      byTool.set(a.tool, arr);
    }
    arr.push(a);
  }
  for (const [tool, acts] of byTool) {
    lines.push(`  ${tool}:`);
    for (const a of acts) {
      const cls = a.cls.toUpperCase().padEnd(11);
      const name = a.action.padEnd(18);
      let detail: string;
      if (a.cls === "active") {
        detail = `last used ${fmtDate(a.lastTs!)} (${a.n}x)`;
        if (fleet?.vetoedKeys.has(evidenceKey(a.tool, a.action))) detail += " (fleet)";
      } else if (a.cls === "stale") detail = `last used ${fmtDate(a.lastTs!)} (${a.n}x) → ${decayVerb}`;
      else if (a.cls === "unused") detail = `never seen in covered window → ${decayVerb}`;
      else detail = "no evidence (log too young/truncated) → keep";
      lines.push(`    ${name} ${cls} ${detail}`);
    }
  }

  const mcpTools = new Set<string>();
  for (const c of report.changes) {
    if (c.disposition === "mcp_skipped") mcpTools.add(c.tool);
    if (c.disposition === "dead") {
      lines.push(`  ${c.tool}: "${c.pattern}" dead — matches no known action (see \`grenz policy lint\`)`);
    }
  }
  for (const t of mcpTools) lines.push(`  ${t}: (generic mcp — report only, no rewrite)`);

  lines.push("");
  lines.push(`  ${report.demotedCount} rule(s) demoted to require_approval, ${report.droppedCount} dropped`);
  if (verified) {
    lines.push(`  ✓ verified: all ${report.activePairs.length} active action(s) decide identically under the proposal`);
  }
  lines.push("  → review, then: grenz policy diff <file> && grenz policy sign <file> --version N+1");
  return lines.join("\n");
}
