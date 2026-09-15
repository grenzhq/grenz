/**
 * Pure policy test runner: assert (tool, action, target) -> decision through
 * the real evaluate() engine. No IO — the CLI shell reads files and passes
 * text in. This is how a policy edit gets a regression net.
 */
import { z } from "zod";
import { parse as parseYaml } from "yaml";
import { evaluate } from "./evaluate.ts";
import type { CompiledPolicy } from "./compile.ts";
import type { Decision, ReasonCode } from "./types.ts";

const DECISIONS = ["allow", "deny", "require_approval"] as const;

const caseSchema = z
  .object({
    name: z.string().min(1).optional(),
    tool: z.string().min(1),
    action: z.string().min(1),
    target: z.string().min(1).optional(),
    expect: z.enum(DECISIONS),
    reason: z.string().min(1).optional(),
  })
  .strict();

const testFileSchema = z.object({ tests: z.array(caseSchema).min(1) }).strict();

export interface PolicyTestCase {
  readonly name?: string;
  readonly tool: string;
  readonly action: string;
  readonly target?: string;
  readonly expect: Decision;
  readonly reason?: ReasonCode;
}

export type ParseResult =
  | { readonly ok: true; readonly cases: PolicyTestCase[] }
  | { readonly ok: false; readonly error: string };

export function parsePolicyTests(yamlText: string): ParseResult {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText);
  } catch (err) {
    return { ok: false, error: `invalid test YAML: ${err instanceof Error ? err.message : String(err)}` };
  }
  const parsed = testFileSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? ` at \`${first.path.join(".")}\`` : "";
    return { ok: false, error: `malformed test file${where}: ${first ? first.message : "invalid"}` };
  }
  // `reason` is validated as a non-empty string here; the runner only ever
  // compares it to a produced ReasonCode, so an unknown string simply never
  // matches (fails the case) rather than throwing.
  return { ok: true, cases: parsed.data.tests as PolicyTestCase[] };
}

export interface PolicyTestResultRow {
  readonly name: string;
  readonly pass: boolean;
  readonly got: { readonly decision: Decision; readonly reason: ReasonCode };
  readonly want: { readonly decision: Decision; readonly reason: ReasonCode | null };
}

export interface PolicyTestResults {
  readonly rows: PolicyTestResultRow[];
  readonly passed: number;
  readonly failed: number;
}

export function runPolicyTests(
  policy: CompiledPolicy,
  cases: readonly PolicyTestCase[],
): PolicyTestResults {
  const rows: PolicyTestResultRow[] = [];
  let passed = 0;
  for (const c of cases) {
    const result = evaluate(policy, { tool: c.tool, action: c.action, target: c.target ?? null });
    const wantReason = c.reason ?? null;
    const pass = result.decision === c.expect && (wantReason === null || result.reason === wantReason);
    if (pass) passed++;
    rows.push({
      name: c.name ?? `${c.tool}:${c.action}`,
      pass,
      got: { decision: result.decision, reason: result.reason },
      want: { decision: c.expect, reason: wantReason },
    });
  }
  return { rows, passed, failed: cases.length - passed };
}
