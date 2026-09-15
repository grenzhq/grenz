/**
 * `grenz blast-radius` — static reachability analysis: expand this agent's
 * glob grants against each adapter's known action vocabulary, and list its
 * live delegated sub-tokens. Answers "what can a leaked GRENZ_TOKEN actually
 * reach right now" — not audit evidence, just current policy laid bare.
 */
import { loadAll, ConfigError } from "../config/load.ts";
import { DelegationStore, DelegationError } from "../delegate/store.ts";
import { analyzeBlastRadius, type BlastRadiusReport } from "../blast-radius/analyze.ts";
import { homeFlag, type ParsedArgs } from "./args.ts";

function formatReport(report: BlastRadiusReport): string {
  const lines: string[] = [`blast radius — ${report.agent} [${report.severity}]`];
  for (const u of report.upstreams) {
    lines.push(``, `${u.upstream} (${u.type})`);
    if (!u.enumerable) {
      lines.push(`  not enumerable — raw grant patterns:`);
      lines.push(`    allow: ${u.rawPatterns?.allow.join(", ") || "(none)"}`);
      lines.push(`    require_approval: ${u.rawPatterns?.requireApproval.join(", ") || "(none)"}`);
      lines.push(`    deny: ${u.rawPatterns?.deny.join(", ") || "(none)"}`);
      continue;
    }
    lines.push(`  auto-allow: ${u.autoAllow.length > 0 ? u.autoAllow.join(", ") : "(none)"}`);
    lines.push(`  requires approval: ${u.requiresApproval.length > 0 ? u.requiresApproval.join(", ") : "(none)"}`);
    for (const bg of u.broadGrants) {
      lines.push(`  ⚠ broad grant "${bg.pattern}" reaches: ${bg.matches.join(", ")}`);
    }
  }
  lines.push(``, `delegations:`);
  if (report.delegations.length === 0) {
    lines.push(`  none active`);
  } else {
    for (const d of report.delegations) {
      lines.push(
        `  ${d.id} [${d.actions.join(", ")}] expires in ${d.expiresInSeconds}s${d.note ? ` — ${d.note}` : ""}`,
      );
    }
  }
  if (report.reasons.length > 0) {
    lines.push(``, `why: ${report.reasons.join("; ")}`);
  }
  return lines.join("\n") + "\n";
}

export async function runBlastRadius(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);
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
  const { paths, config, policy } = loaded;
  const agent = args.positionals[0] ?? policy.agent;

  let delegations: DelegationStore | null = null;
  if (await Bun.file(paths.delegations).exists()) {
    try {
      delegations = new DelegationStore(paths.delegations);
    } catch (err) {
      if (err instanceof DelegationError) {
        process.stderr.write(`grenz: ${err.message}\n`);
        return 1;
      }
      throw err;
    }
  }

  const now = Date.now();
  const report = analyzeBlastRadius({
    agent,
    upstreams: config.upstreams,
    policy,
    delegations:
      delegations?.list(now).map((d) => ({
        id: d.id,
        parentAgentId: d.parentAgentId,
        note: d.note,
        actions: d.actions,
        expiresAt: d.expiresAt,
      })) ?? [],
    now,
  });

  process.stdout.write(formatReport(report));
  return 0;
}
