/**
 * `grenz policy` — validate, lint, and simulate policy changes.
 *
 *   check          Validate + compile the policy, print a summary.
 *   lint           Static checks over the active policy: dead patterns,
 *                  shadowed rules, overly broad grants, and per-agent budget/
 *                  approval keys that name no registered agent. Warnings (exit 0).
 *   diff <file>    Lint a candidate policy file, then replay it against
 *                  historical (tool, action) pairs from the request log to
 *                  show what would actually change.
 *   keygen         Generate an Ed25519 signing keypair for fleet distribution.
 *   sign <file>    Sign a policy into a versioned bundle the plane can serve
 *                  (--key, --version, --profile name=path[,name=path...],
 *                  --clear-profiles, --force-version).
 *   push           Upload a signed bundle to the plane (--bundle <file>|-,
 *                  --url, --token|--token-key|$GRENZ_PUBLISH_TOKEN).
 */
import { rename } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { resolve, dirname, basename, join } from "node:path";
import { loadAll, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { compilePolicyYaml, compilePolicyObject } from "../policy/compile.ts";
import { evaluate } from "../policy/evaluate.ts";
import { shrinkwrapPolicy } from "../policy/shrinkwrap.ts";
import { decayPolicy, formatDecayReport, evidenceKey, type DecayMode, type FleetContext } from "../policy/decay.ts";
import { buildEvidenceDoc, serializeEvidenceDoc, parseEvidenceDoc } from "../policy/decay-evidence.ts";
import { actionVocabulary } from "../adapters/vocabulary.ts";
import { stringify as stringifyYaml } from "yaml";
import {
  lintPolicy,
  lintExec,
  lintWeights,
  lintFlows,
  lintTripwires,
  lintPins,
  lintResponses,
  lintDecoys,
  lintPerAgentKeys,
  type LintFinding,
  type WeightLintFinding,
  type FlowLintFinding,
  type TripwireLintFinding,
  type PinLintFinding,
  type ResponseLintFinding,
  type DecoyLintFinding,
  type PerAgentKeyLintFinding,
  type ExecLintFinding,
} from "../policy/lint.ts";
import { diffPolicies, type DiffPair } from "../policy/diff.ts";
import { parsePolicyTests, runPolicyTests } from "../policy/test-runner.ts";
import { PolicyHistoryStore } from "../policy/history-store.ts";
import { planRollback } from "../policy/rollback.ts";
import { shortHash } from "../policy/history.ts";
import { RequestLog } from "../log/request-log.ts";
import { flagBool, flagString, homeFlag, type ParsedArgs } from "./args.ts";
import { adminClient, callAdmin } from "./admin-client.ts";
import { runPolicyKeygen, runPolicySign } from "./policy-sign.ts";
import { runPolicyPush } from "./policy-push.ts";

function formatFindings(
  findings: readonly LintFinding[],
  weightFindings: readonly WeightLintFinding[] = [],
  flowFindings: readonly FlowLintFinding[] = [],
  tripwireFindings: readonly TripwireLintFinding[] = [],
  pinFindings: readonly PinLintFinding[] = [],
  responseFindings: readonly ResponseLintFinding[] = [],
  decoyFindings: readonly DecoyLintFinding[] = [],
  perAgentFindings: readonly PerAgentKeyLintFinding[] = [],
  execFindings: readonly ExecLintFinding[] = [],
): string[] {
  if (
    findings.length === 0 &&
    weightFindings.length === 0 &&
    flowFindings.length === 0 &&
    tripwireFindings.length === 0 &&
    pinFindings.length === 0 &&
    responseFindings.length === 0 &&
    decoyFindings.length === 0 &&
    perAgentFindings.length === 0 &&
    execFindings.length === 0
  ) {
    return ["  clean, no findings"];
  }
  return [
    ...findings.map((f) => `  [${f.kind}] ${f.tool} "${f.pattern}": ${f.detail}`),
    ...weightFindings.map((f) => `  [${f.kind}] budget.weights "${f.pattern}": ${f.detail}`),
    ...flowFindings.map((f) => `  [dead_flow] flow ${f.side} "${f.pattern}": ${f.detail}`),
    ...tripwireFindings.map((f) => `  [tripwire_overlap] tripwire "${f.pattern}": ${f.detail}`),
    ...pinFindings.map((f) => `  [dead_pin] pin rule ${f.ruleIndex} on "${f.pattern}": ${f.detail}`),
    ...responseFindings.map((f) => `  [dead_response] responses rule ${f.ruleIndex} on "${f.pattern}": ${f.detail}`),
    ...decoyFindings.map((f) => `  [decoy_grant] grant "${f.pattern}": ${f.detail}`),
    ...perAgentFindings.map((f) => `  [dead_per_agent_key] ${f.map} "${f.agentId}": ${f.detail}`),
    ...execFindings.map((f) => `  [${f.kind}] bash ${f.clause} "${f.pattern}": ${f.detail}`),
  ];
}

async function runCheck(args: ParsedArgs): Promise<number> {
  let loaded;
  try {
    loaded = await loadAll(homeFlag(args));
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const policy = loaded.policy;

  const lines: string[] = [
    `policy OK`,
    `  agent:        ${policy.agent}`,
    `  on behalf of: ${policy.onBehalfOf}`,
    `  budget:       ${policy.maxActionsPerHour === null ? "unlimited" : `${policy.maxActionsPerHour}/hr`}`,
    `  grants:`,
  ];
  for (const grant of policy.grants.values()) {
    lines.push(
      `    - ${grant.tool}: ${grant.allow.length} allow, ${grant.deny.length} deny, ` +
        `${grant.requireApproval.length} require_approval`,
    );
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}

async function runLint(args: ParsedArgs): Promise<number> {
  let loaded;
  try {
    loaded = await loadAll(homeFlag(args));
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const findings = lintPolicy(loaded.policy, loaded.config.upstreams);
  const weightFindings = lintWeights(loaded.policy, loaded.config.upstreams);
  const flowFindings = lintFlows(loaded.policy, loaded.config.upstreams);
  const tripwireFindings = lintTripwires(loaded.policy, loaded.config.upstreams);
  const pinFindings = lintPins(loaded.policy, loaded.config.upstreams);
  const responseFindings = lintResponses(loaded.policy, loaded.config.upstreams);
  const decoyFindings = lintDecoys(loaded.policy, loaded.config.upstreams);
  const perAgentFindings = lintPerAgentKeys(
    loaded.policy,
    loaded.config.agents.map((a) => a.id),
  );
  const execFindings = lintExec(loaded.policy);
  process.stdout.write(
    [
      "policy lint —",
      ...formatFindings(
        findings,
        weightFindings,
        flowFindings,
        tripwireFindings,
        pinFindings,
        responseFindings,
        decoyFindings,
        perAgentFindings,
        execFindings,
      ),
    ].join("\n") + "\n",
  );
  return 0;
}

async function runDiff(args: ParsedArgs): Promise<number> {
  const candidatePath = args.positionals[1];
  if (!candidatePath) {
    process.stderr.write("grenz: usage: grenz policy diff <file>\n");
    return 1;
  }

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

  const candidateFile = Bun.file(candidatePath);
  if (!(await candidateFile.exists())) {
    process.stderr.write(`grenz: candidate policy not found at ${candidatePath}\n`);
    return 1;
  }
  const compiled = compilePolicyYaml(await candidateFile.text());
  if (!compiled.ok) {
    process.stderr.write(`grenz: candidate policy invalid: ${compiled.error}\n`);
    return 1;
  }
  const candidate = compiled.policy;

  const lines: string[] = [`policy diff — ${candidatePath} vs active policy`, ``, `lint (candidate):`];
  lines.push(
    ...formatFindings(
      lintPolicy(candidate, loaded.config.upstreams),
      lintWeights(candidate, loaded.config.upstreams),
      lintFlows(candidate, loaded.config.upstreams),
      lintTripwires(candidate, loaded.config.upstreams),
      lintPins(candidate, loaded.config.upstreams),
      lintResponses(candidate, loaded.config.upstreams),
      lintDecoys(candidate, loaded.config.upstreams),
      lintPerAgentKeys(
        candidate,
        loaded.config.agents.map((a) => a.id),
      ),
    ),
  );

  const hoursFlag = flagString(args, "hours");
  const hours = Number(hoursFlag ?? 0);
  const sinceTs = Number.isFinite(hours) && hours > 0 ? Date.now() - hours * 60 * 60 * 1000 : 0;

  lines.push(``, `replay against history:`);
  const paths = grenzPaths(home);
  if (!(await Bun.file(paths.db).exists())) {
    lines.push("  no request log yet — start the proxy with `grenz run`");
  } else {
    const log = new RequestLog(paths.db);
    const rows = log.aggregate(sinceTs);
    log.close();
    const pairs: DiffPair[] = rows.map((r) => ({ tool: r.tool, action: r.action }));
    const countByPair = new Map(
      rows.map((r) => [`${r.tool} ${r.action}`, r.allow + r.deny + r.require_approval]),
    );
    const diff = diffPolicies(loaded.policy, candidate, pairs);
    if (diff.length === 0) {
      lines.push("  no changes — candidate behaves identically to active policy over history");
    } else {
      for (const d of diff) {
        const count = countByPair.get(`${d.tool} ${d.action}`) ?? 0;
        lines.push(
          `  ${d.tool}:${d.action}  ${d.from} -> ${d.to}  (${count} historical occurrence${count === 1 ? "" : "s"})`,
        );
      }
    }
  }

  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}

async function runHistory(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);
  const store = new PolicyHistoryStore(paths.policyHistory);
  const snapshots = store.list();

  let currentHash: string | null = null;
  const policyFile = Bun.file(paths.policy);
  if (await policyFile.exists()) currentHash = shortHash(await policyFile.text());

  const lines: string[] = ["policy history —"];
  if (snapshots.length === 0) {
    lines.push("  (no snapshots yet — start the proxy with `grenz run` to capture one)");
  } else {
    for (const s of snapshots) {
      const mark = currentHash !== null && s.hash === currentHash ? "  (current)" : "";
      lines.push(`  ${s.index}  ${s.stamp}  ${s.hash}  ${s.bytes}B${mark}`);
    }
  }
  if (currentHash !== null && !snapshots.some((s) => s.hash === currentHash)) {
    lines.push("", "  working policy.yaml is not yet snapshotted (start/reload the proxy to capture it)");
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}

async function runRollback(args: ParsedArgs): Promise<number> {
  const n = Number(args.positionals[1]);
  if (!Number.isInteger(n) || n < 1) {
    process.stderr.write("grenz: usage: grenz policy rollback <n> [--yes]\n");
    return 1;
  }
  const home = homeFlag(args);
  const paths = grenzPaths(home);
  const store = new PolicyHistoryStore(paths.policyHistory);

  const candidateText = store.read(n);
  if (candidateText === null) {
    process.stderr.write(`grenz: no snapshot #${n} (see \`grenz policy history\`)\n`);
    return 1;
  }

  const policyFile = Bun.file(paths.policy);
  const currentText = (await policyFile.exists()) ? await policyFile.text() : "";

  // Historical (tool, action) pairs for the semantic diff (same as `policy diff`).
  const pairs: DiffPair[] = [];
  if (await Bun.file(paths.db).exists()) {
    const log = new RequestLog(paths.db);
    for (const r of log.aggregate(0)) pairs.push({ tool: r.tool, action: r.action });
    log.close();
  }

  const plan = planRollback(currentText, candidateText, pairs);
  if (!plan.ok) {
    process.stderr.write(`grenz: ${plan.reason}\n`);
    return 1;
  }

  const lines: string[] = [];
  if (!plan.currentCompiles) {
    lines.push("  note: current policy.yaml does not compile — rolling back to a snapshot that does");
  }
  if (plan.diff.length === 0) {
    lines.push("  no decision changes over recorded history");
  } else {
    lines.push("  decision changes if applied:");
    for (const d of plan.diff) lines.push(`    ${d.tool}:${d.action}  ${d.from} -> ${d.to}`);
  }

  const apply = flagBool(args, "yes");
  if (!apply) {
    process.stdout.write(
      [`policy rollback #${n} — [dry run]`, ...lines, "", "  re-run with --yes to apply"].join("\n") + "\n",
    );
    return 0;
  }

  // Snapshot the current file first so the rollback is itself reversible, then
  // atomically restore the snapshot (temp + rename — the rotate.ts pattern).
  if (currentText.length > 0) store.record(currentText, Date.now());
  const tmp = `${paths.policy}.tmp`;
  await Bun.write(tmp, candidateText);
  await rename(tmp, paths.policy);

  process.stdout.write(
    [`policy rollback #${n} — applied`, ...lines, "", `  restored ${paths.policy}`].join("\n") + "\n",
  );
  return 0;
}

async function runTest(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);
  // Positional[0] is "test"; [1] is the optional test-file path.
  const testPath = args.positionals[1] ?? paths.policyTests;

  const testFile = Bun.file(testPath);
  if (!(await testFile.exists())) {
    process.stderr.write(`grenz: no test file at ${testPath}\n`);
    return 1;
  }
  const parsed = parsePolicyTests(await testFile.text());
  if (!parsed.ok) {
    process.stderr.write(`grenz: ${parsed.error}\n`);
    return 1;
  }

  // Resolve the policy under test: --policy candidate, else the active policy.
  const candidatePath = flagString(args, "policy");
  let policy;
  if (candidatePath !== undefined) {
    const cf = Bun.file(candidatePath);
    if (!(await cf.exists())) {
      process.stderr.write(`grenz: candidate policy not found at ${candidatePath}\n`);
      return 1;
    }
    const compiled = compilePolicyYaml(await cf.text());
    if (!compiled.ok) {
      process.stderr.write(`grenz: candidate policy invalid: ${compiled.error}\n`);
      return 1;
    }
    policy = compiled.policy;
  } else {
    try {
      policy = (await loadAll(home)).policy;
    } catch (err) {
      if (err instanceof ConfigError) {
        process.stderr.write(`grenz: ${err.message}\n`);
        return 1;
      }
      throw err;
    }
  }

  const results = runPolicyTests(policy, parsed.cases);
  const lines = [`policy test — ${testPath}${candidatePath ? ` (candidate ${candidatePath})` : ""}`, ``];
  for (const r of results.rows) {
    lines.push(
      r.pass
        ? `  ok    ${r.name}`
        : `  FAIL  ${r.name}: got ${r.got.decision} (${r.got.reason}), want ${r.want.decision}` +
            (r.want.reason ? ` (${r.want.reason})` : ""),
    );
  }
  lines.push(``, `${results.passed} passed, ${results.failed} failed`);
  process.stdout.write(lines.join("\n") + "\n");
  return results.failed === 0 ? 0 : 1;
}

async function runShrinkwrap(args: ParsedArgs): Promise<number> {
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
  const agentId = flagString(args, "agent") ?? loaded.policy.agent;
  const hours = Number(flagString(args, "hours") ?? 0);
  const sinceTs = Number.isFinite(hours) && hours > 0 ? Date.now() - hours * 60 * 60 * 1000 : 0;

  const paths = grenzPaths(home);
  if (!(await Bun.file(paths.db).exists())) {
    process.stderr.write("grenz: no request log yet — run some traffic through the proxy first\n");
    return 1;
  }
  const log = new RequestLog(paths.db);
  const rows = log.usedActions(agentId, sinceTs);
  log.close();

  const used = new Map<string, Set<string>>();
  for (const { tool, action } of rows) {
    let set = used.get(tool);
    if (!set) {
      set = new Set();
      used.set(tool, set);
    }
    set.add(action);
  }

  const tightened = shrinkwrapPolicy(loaded.policy.source, used);

  // Verify: the tightened policy must still permit every used action.
  const recompiled = compilePolicyObject(tightened);
  if (!recompiled.ok) {
    process.stderr.write(`grenz: shrinkwrap produced an invalid policy: ${recompiled.error}\n`);
    return 1;
  }
  let denied = 0;
  for (const { tool, action } of rows) {
    if (evaluate(recompiled.policy, { tool, action, target: null }).decision === "deny") denied++;
  }
  if (denied > 0) {
    process.stderr.write(`grenz: shrinkwrap verification failed — ${denied} used action(s) would be denied\n`);
    return 1;
  }

  // Delta summary -> stderr, so stdout stays clean YAML.
  process.stderr.write(`shrinkwrap — agent ${agentId}${hours > 0 ? ` (last ${hours}h)` : ""}\n`);
  for (const grant of loaded.policy.grants.values()) {
    const usedCount = used.get(grant.tool)?.size ?? 0;
    const vocabulary = actionVocabulary(loaded.config.upstreams[grant.tool]?.type ?? "");
    if (vocabulary) {
      const reachable = vocabulary.filter((a) => grant.allow.some((r) => r.action.re.test(a))).length;
      process.stderr.write(
        `  ${grant.tool}: ${reachable} reachable → ${usedCount} used (dropped ${Math.max(0, reachable - usedCount)})\n`,
      );
    } else {
      process.stderr.write(`  ${grant.tool}: ${usedCount} used\n`);
    }
  }
  process.stderr.write(`  ✓ verified: ${rows.length} used action(s) still permitted\n`);
  process.stderr.write(`  → review, then: grenz policy diff <file>\n`);

  const yaml = stringifyYaml(tightened);
  const outFile = flagString(args, "out");
  if (outFile) {
    await Bun.write(outFile, yaml);
    process.stderr.write(`  written to ${outFile}\n`);
  } else {
    process.stdout.write(yaml);
  }
  return 0;
}

/**
 * Whether `candidate` resolves to the same file as `existing`. Compares realpaths
 * (symlink- and case-resolved) — the candidate may not exist yet, so its parent
 * dir is realpath'd and rejoined with the basename. Falls back to a plain resolve
 * compare if a realpath lookup throws (missing parent, permissions).
 */
function sameFile(candidate: string, existing: string): boolean {
  if (resolve(candidate) === resolve(existing)) return true;
  try {
    const candReal = join(realpathSync(dirname(candidate)), basename(candidate));
    const existReal = realpathSync(existing);
    return candReal === existReal;
  } catch {
    return false;
  }
}

async function runDecayExport(args: ParsedArgs): Promise<number> {
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
  const agentId = flagString(args, "agent") ?? loaded.policy.agent;
  const proxyLabel = flagString(args, "proxy");
  const paths = grenzPaths(home);
  if (!(await Bun.file(paths.db).exists())) {
    process.stderr.write("grenz: no request log yet — run some traffic through the proxy first\n");
    return 1;
  }
  const log = new RequestLog(paths.db);
  const rows = log.lastUsedActions(agentId);
  log.close();

  const doc = buildEvidenceDoc(agentId, proxyLabel, Date.now(), rows);
  const text = serializeEvidenceDoc(doc);
  const outFile = flagString(args, "out");
  if (outFile) {
    await Bun.write(outFile, text);
    process.stderr.write(`  exported ${doc.actions.length} action(s) for agent ${agentId} to ${outFile}\n`);
  } else {
    process.stdout.write(text);
  }
  return 0;
}

async function runDecay(args: ParsedArgs): Promise<number> {
  if (args.positionals[1] === "export") return runDecayExport(args);
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

  const agentId = flagString(args, "agent") ?? loaded.policy.agent;
  const staleDays = Number(flagString(args, "stale-days") ?? 30);
  if (!Number.isFinite(staleDays) || staleDays <= 0) {
    process.stderr.write("grenz: --stale-days must be a positive number\n");
    return 1;
  }
  const mode: DecayMode = flagBool(args, "drop") ? "drop" : "demote";
  const paths = grenzPaths(home);

  // --out must never target the live policy.yaml (self-mutation footgun). Checked
  // before touching the log so the refusal fires regardless of log state. Compare
  // by realpath (following symlinks; canonical case on a case-insensitive FS) so a
  // symlinked dir or a case variant cannot slip past a plain string compare.
  const outFile = flagString(args, "out");
  if (outFile !== undefined && sameFile(outFile, paths.policy)) {
    process.stderr.write(
      "grenz: refusing to write decay output over the live policy.yaml — review it, then apply via " +
        "`grenz policy diff` + `grenz policy sign`, or a hand-edit under --watch\n",
    );
    return 1;
  }

  if (!(await Bun.file(paths.db).exists())) {
    process.stderr.write("grenz: no request log yet — run some traffic through the proxy first\n");
    return 1;
  }

  const log = new RequestLog(paths.db);
  const rows = log.lastUsedActions(agentId);
  // Per-agent coverage: the honest observation window for THIS agent, so a renamed
  // or freshly-added agent does not inherit the whole log's age (which would judge
  // its never-re-exercised grants "stale").
  const coverageStart = log.coverageStart(agentId);
  log.close();

  const lastUsed = new Map<string, { lastTs: number; n: number }>();
  let agentUsageRows = 0;
  for (const r of rows) {
    lastUsed.set(evidenceKey(r.tool, r.action), { lastTs: r.lastTs, n: r.n });
    agentUsageRows += r.n; // LOCAL only — the zero-usage guard never counts fleet rows
  }

  const now = Date.now();
  const staleBefore = now - staleDays * 86_400_000;
  // covered is a LOCAL, per-agent property — fleet evidence never extends it.
  const covered = coverageStart !== null && coverageStart <= staleBefore;

  // Fleet evidence (--evidence f1,f2): merge peer usage. A demotion VETO ONLY. It
  // RAISES a per-action lastTs to ACTIVE for exactly the actions that WOULD decay
  // locally (covered log, locally stale/absent) and are fresh on a peer — nothing
  // else. It never lowers a timestamp, never extends coverage, never touches the
  // zero-usage guard. So it can only suppress a demotion, never introduce one, and
  // a raised timestamp is never presented as this proxy's own (no non-veto smudge).
  let fleet: FleetContext | undefined;
  const evidenceFlag = flagString(args, "evidence");
  if (evidenceFlag !== undefined) {
    const files = evidenceFlag.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
    const contributors: string[] = [];
    // Pass 1: union all accepted files into the fleet max (independent of local),
    // so multi-file freshness is order-independent.
    const fleetMax = new Map<string, number>();
    for (const f of files) {
      const file = Bun.file(f);
      if (!(await file.exists())) {
        process.stderr.write(`grenz: evidence file not found: ${f}\n`);
        return 1;
      }
      const parsed = parseEvidenceDoc(await file.text());
      if (!parsed.ok) {
        process.stderr.write(`grenz: ${parsed.error} (${f})\n`);
        return 1;
      }
      if (parsed.doc.agent !== agentId) {
        process.stderr.write(
          `grenz: skipping evidence for agent "${parsed.doc.agent}" (${f}) — decaying "${agentId}"\n`,
        );
        continue;
      }
      const label = parsed.doc.proxy ?? f;
      contributors.push(label);
      // A snapshot older than the whole staleness window tells you nothing about
      // whether that peer uses these actions NOW — its recorded uses all predate
      // the window, so it both under-represents the peer and cannot veto. Warn so a
      // stale export is not mistaken for live coverage.
      const ageDays = Math.floor((now - parsed.doc.generatedAt) / 86_400_000);
      if (now - parsed.doc.generatedAt > staleDays * 86_400_000) {
        process.stderr.write(
          `grenz: ⚠ evidence "${label}" was exported ${ageDays}d ago (> ${staleDays}d window) — ` +
            `that proxy's activity since is unknown; re-export before relying on it\n`,
        );
      }
      for (const a of parsed.doc.actions) {
        const k = evidenceKey(a.tool, a.action);
        const prev = fleetMax.get(k);
        if (prev === undefined || a.lastTs > prev) fleetMax.set(k, a.lastTs);
      }
    }
    // Pass 2: veto-only merge against the ORIGINAL local evidence.
    const vetoedKeys = new Set<string>();
    for (const [k, fleetTs] of fleetMax) {
      const local = lastUsed.get(k);
      const localTs = local ? local.lastTs : null;
      const wouldDecay = covered && (localTs === null || localTs < staleBefore);
      if (wouldDecay && fleetTs >= staleBefore) {
        lastUsed.set(k, { lastTs: fleetTs, n: local ? local.n : 0 });
        vetoedKeys.add(k);
      }
    }
    fleet = { files: contributors, vetoedKeys };
  }

  const vocabularies = new Map<string, readonly string[] | null>();
  for (const grant of loaded.policy.grants.values()) {
    vocabularies.set(grant.tool, actionVocabulary(loaded.config.upstreams[grant.tool]?.type ?? ""));
  }

  const result = decayPolicy(
    loaded.policy.source,
    vocabularies,
    { lastUsed, coverageStart, agentUsageRows },
    { now, staleDays, mode, agentId },
  );
  if (!result.ok) {
    process.stderr.write(`grenz: ${result.reason}\n`);
    return 1;
  }

  // Verify (differential): every ACTIVE action must decide identically before and
  // after. `target: null` is reachability mode, so an active action shadowed by a
  // target-scoped require_approval decides identically both ways and is not
  // false-flagged — while a genuine allow->deny/approval regression is caught.
  const recompiled = compilePolicyObject(result.source);
  if (!recompiled.ok) {
    process.stderr.write(`grenz: decay produced an invalid policy: ${recompiled.error}\n`);
    return 1;
  }
  let changed = 0;
  for (const { tool, action } of result.report.activePairs) {
    const before = evaluate(loaded.policy, { tool, action, target: null }).decision;
    const after = evaluate(recompiled.policy, { tool, action, target: null }).decision;
    if (before !== after) changed += 1;
  }
  if (changed > 0) {
    process.stderr.write(`grenz: decay verification failed — ${changed} active action(s) would change decision\n`);
    return 1;
  }

  process.stderr.write(formatDecayReport(result.report, true, fleet) + "\n");

  // Fleet honesty: under signed distribution this proxy's log is only ONE slice of
  // the fleet's traffic — an action idle here may be busy on a peer. The wording
  // acknowledges merged evidence (peers you did NOT export are still unrepresented)
  // vs a single-proxy run, so it never contradicts the fleet header above.
  if (loaded.config.policy_source !== undefined) {
    const basis = fleet && fleet.files.length > 0 ? "the proxies you merged" : "THIS proxy's log alone";
    const unrep = fleet && fleet.files.length > 0 ? "a proxy you did not export is" : "another proxy is";
    if (mode === "drop") {
      process.stderr.write(
        `\n  ⚠ FLEET + --drop: this candidate DROPS grants based on ${basis}. An action idle in\n` +
          `    that evidence may be in active use where ${unrep} unrepresented — dropping it, then\n` +
          "    signing, DENIES it fleet-wide with no approval fallback. Prefer demote (omit --drop)\n" +
          "    or confirm against every proxy's usage before signing.\n",
      );
    } else {
      process.stderr.write(
        `\n  ⚠ fleet mode: evidence is from ${basis}. A demoted grant an agent uses where\n` +
          `    ${unrep} unrepresented becomes an approval prompt there — review peer usage before signing.\n`,
      );
    }
  }

  if (flagBool(args, "report-only")) return 0;

  const yaml = stringifyYaml(result.source);
  if (outFile) {
    await Bun.write(outFile, yaml);
    process.stderr.write(`  written to ${outFile}\n`);
  } else {
    process.stdout.write(yaml);
  }
  return 0;
}

interface CanaryRow {
  readonly tool: string;
  readonly action: string;
  readonly live: string;
  readonly candidate: string;
  readonly direction: "stricter" | "looser";
  readonly count: number;
}
type CanaryBody =
  | { readonly configured: false }
  | { readonly requests: number; readonly divergences: number; readonly rows: readonly CanaryRow[] };

/** Pure formatter for the `grenz policy canary` report. */
export function renderCanary(body: CanaryBody): string {
  if (!("rows" in body)) {
    return "grenz: no canary configured — start the proxy with --canary <file>\n";
  }
  const { requests, divergences, rows } = body;
  const head = `canary — ${requests} requests observed, ${divergences} divergences`;
  if (divergences === 0 || rows.length === 0) {
    return `${head}\n✓ no divergences — the candidate would decide every observed request identically\n`;
  }
  const stricter = rows.filter((r) => r.direction === "stricter");
  const looser = rows.filter((r) => r.direction === "looser");
  const line = (r: CanaryRow) => `    ${r.tool} ${r.action}  ${r.live} → ${r.candidate}  ${r.count}×`;
  const parts = [head];
  if (stricter.length > 0) {
    parts.push("  would newly BLOCK (promotion risk):", ...stricter.map(line));
  }
  if (looser.length > 0) {
    parts.push("  would newly ALLOW (widening):", ...looser.map(line));
  }
  parts.push("  → if the BLOCK list is all expected, apply the candidate (diff, then --watch)");
  return parts.join("\n") + "\n";
}

async function runCanary(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await callAdmin(client, "GET", "/console/canary");
  if (!res) return 1;
  process.stdout.write(renderCanary(res.body as CanaryBody));
  return 0;
}

export async function runPolicy(args: ParsedArgs): Promise<number> {
  const sub = args.positionals[0];
  if (sub === "check") return runCheck(args);
  if (sub === "lint") return runLint(args);
  if (sub === "diff") return runDiff(args);
  if (sub === "test") return runTest(args);
  if (sub === "history") return runHistory(args);
  if (sub === "rollback") return runRollback(args);
  if (sub === "shrinkwrap") return runShrinkwrap(args);
  if (sub === "decay") return runDecay(args);
  if (sub === "canary") return runCanary(args);
  if (sub === "keygen") return runPolicyKeygen(args);
  if (sub === "sign") return runPolicySign(args);
  if (sub === "push") return runPolicyPush(args);
  process.stderr.write(
    "grenz: usage: grenz policy check|lint|diff <file>|test [file]|history|rollback <n>|shrinkwrap|decay|canary|keygen|sign <file>|push\n",
  );
  return 1;
}
