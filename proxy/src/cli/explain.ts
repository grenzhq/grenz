/**
 * `grenz explain <tool> <action> [target]` — why would this be allowed or denied right
 * now? Read-only, offline: traces the pair through the same layers dispatch()
 * applies (kill-switch -> engine -> JIT grants -> step-up -> budgets) using
 * local state only. A viewer, not a gate — it never writes anything.
 */
import { loadAll, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { RequestLog } from "../log/request-log.ts";
import { RevocationStore, RevocationError } from "../revoke/store.ts";
import { GrantStore, GrantError } from "../grant/store.ts";
import { buildExplain, type ExplainReport } from "../explain/report.ts";
import { collectExplainInputs } from "../explain/inputs.ts";
import type { CompiledPolicy } from "../policy/compile.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

const GRANT_EFFECT_TEXT: Record<NonNullable<ExplainReport["grantEffect"]>, string> = {
  widens_gap: "fills the policy gap (allow via jit_grant)",
  widens_approval: "lifts the approval (allow via jit_grant)",
  never_overrides_deny: "matches, but a grant never overrides an explicit deny",
  not_needed: "matches, but the policy already allows",
};

export async function runExplain(args: ParsedArgs): Promise<number> {
  const tool = args.positionals[0];
  const action = args.positionals[1];
  // Optional: a concrete target to test. Omitted -> worst-case reachability
  // (target-scoped allows/approvals count as matchable, scoped denies as
  // evadable), and the output notes any target-conditional rules.
  const target = args.positionals[2] ?? null;
  if (!tool || !action) {
    process.stderr.write("grenz: usage: grenz explain <tool> <action> [target] [--agent <id>]\n");
    return 1;
  }

  const home = homeFlag(args);
  const paths = grenzPaths(home);

  let loaded;
  try {
    loaded = await loadAll(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const policy = loaded.policy;
  const agentId = flagString(args, "agent") ?? policy.agent;
  const now = Date.now();

  // Kill-switch + grants: fail closed on corrupt state, same as `grenz run`.
  let revocations: RevocationStore;
  try {
    revocations = new RevocationStore(paths.revocations);
  } catch (err) {
    if (err instanceof RevocationError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  let grants: GrantStore;
  try {
    grants = new GrantStore(paths.grants);
  } catch (err) {
    if (err instanceof GrantError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  // Assemble the explain inputs via the SHARED collector (the same one
  // `/console/explain` uses over live state) so the CLI and the console can
  // never diverge. Open the log only when the DB exists; null otherwise.
  const log = (await Bun.file(paths.db).exists()) ? new RequestLog(paths.db) : null;
  const report = buildExplain(
    collectExplainInputs({
      policy,
      agentId,
      tool,
      action,
      target,
      now,
      log,
      revocations,
      grants,
      approvals: {
        ttlSeconds: loaded.config.approvals.ttl_seconds,
        rememberSeconds: loaded.config.approvals.remember_seconds,
      },
    }),
  );
  log?.close();

  process.stdout.write(
    renderExplainLines(report, { agentId, tool, action, target, policy }).join("\n") + "\n",
  );
  return 0;
}

/** Context the CLI renderer needs beyond the report: the request coordinates and
 *  the compiled policy (for schedule/first-use display). */
export interface ExplainRenderContext {
  readonly agentId: string;
  readonly tool: string;
  readonly action: string;
  readonly target: string | null;
  readonly policy: CompiledPolicy;
}

/** Render an ExplainReport to human-readable lines. Pure — returns the lines
 *  (rather than writing them) so the output is unit-testable; the command joins
 *  and writes them. */
export function renderExplainLines(report: ExplainReport, ctx: ExplainRenderContext): string[] {
  const { agentId, tool, action, target, policy } = ctx;
  const lines: string[] = [
    `explain ${agentId} -> ${tool}:${action}${target !== null ? ` @ ${target}` : ""}`,
  ];
  lines.push(`  verdict now:  ${report.effective.decision.toUpperCase()} (${report.effective.reason})`);
  if (report.scopedRules > 0 && target === null) {
    lines.push(
      `  note: ${report.scopedRules} target-scoped rule(s) cover this action — ` +
        `verdict above is worst-case; pass a target to test one`,
    );
  }
  const patt = report.engine.pattern
    ? ` — matched ${report.engine.matched} "${report.engine.pattern}"`
    : "";
  lines.push(`  policy:       ${report.engine.decision} (${report.engine.reason})${patt}`);
  if (report.engine.message) {
    // The matched rule's operator-authored remediation hint (also sent to the
    // agent on a deny via `x-grenz-hint`).
    lines.push(`  hint:         ${report.engine.message}`);
  }
  lines.push(
    `  kill-switch:  ${report.revoked ? "REVOKED — everything denied at the door" : "not revoked"}`,
  );
  if (report.grantMatch && report.grantEffect) {
    lines.push(
      `  jit grant:    ${report.grantMatch.id} "${report.grantMatch.pattern}" — ${GRANT_EFFECT_TEXT[report.grantEffect]}`,
    );
  } else {
    lines.push(`  jit grant:    none active for this action`);
  }
  const ab = report.agentBudget;
  lines.push(
    `  budget:       agent ${ab.spent}/${ab.limit ?? "unlimited"} this hour` +
      `${ab.override ? " (per-agent override)" : ""}` +
      `${ab.cost > 1 ? ` (this action costs ${ab.cost})` : ""}` +
      `${ab.wouldExceed ? " — EXCEEDED" : ""}`,
  );
  if (report.upstreamBudget) {
    const ub = report.upstreamBudget;
    lines.push(
      `                ${tool} ${ub.spent}/${ub.limit} this hour${ub.wouldExceed ? " — EXCEEDED" : ""}`,
    );
  }
  if (report.stepUp) {
    lines.push(
      `  step-up:      configured (${Math.round(report.stepUp.windowMs / 60_000)}m window), ` +
        `current risk ${report.stepUp.riskLevel ?? "unknown (no log yet)"}` +
        `${report.stepUp.wouldUpgrade ? " — an allow would UPGRADE to approval" : ""}`,
    );
  }
  if (report.perAgentApproval) {
    lines.push(
      `  per-agent:    ${agentId}'s overlay clamps ${action} → require_approval (always asks)`,
    );
  }
  if (policy.schedule && report.scheduleOpen !== null) {
    lines.push(
      `  schedule:     ${policy.schedule.timezone}, ` +
        `${report.scheduleOpen ? "OPEN" : `CLOSED — on_closed = ${policy.schedule.onClosed}`}`,
    );
  }
  if (policy.firstUse && report.firstUseSeen !== null) {
    lines.push(
      `  first-use:    ${report.firstUseSeen ? "seen in local log" : `FIRST USE — on_first = ${policy.firstUse.onFirst}`}`,
    );
  }
  if (report.tripwire) {
    lines.push(
      `  tripwire:     ATTEMPTING THIS REVOKES ${agentId}` +
        `${report.tripwire.note ? ` (note: ${report.tripwire.note})` : ""}`,
    );
  }
  for (const fs of report.flowSinks) {
    lines.push(
      `  flow:         sink for a ${fs.effect === "deny" ? "DENY" : "require_approval"} flow ` +
        `(sources: ${fs.sources.join(", ")}); gated if a source was seen within ${fs.withinSeconds}s this session`,
    );
  }
  for (const p of report.pins) {
    lines.push(
      `  pin:          constrained by pin rule ${p.ruleIndex} — must stay on the ` +
        `first-touched unit this session; a new unit → ${p.effect === "deny" ? "DENY" : "require_approval"}`,
    );
  }
  if (report.responseCap !== null) {
    lines.push(
      `  responses:    cap ${report.responseCap.maxBytes}B ` +
        `(${report.responseCap.onExceed === "deny" ? "over-cap → DENY" : "truncate over cap"})`,
    );
  }
  if (report.effective.decision === "require_approval") {
    lines.push(
      `  approval:     ttl ${report.approvals.ttlSeconds}s, remember ` +
        `${report.approvals.rememberSeconds > 0 ? `${report.approvals.rememberSeconds}s` : "off"}`,
    );
  }
  lines.push(`  note:         DLP (body) and egress (URL) checks depend on the concrete request`);
  return lines;
}
