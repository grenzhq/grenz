/**
 * Policy diff — replay a set of (tool, action) pairs against two policies and
 * report where the decision actually changes.
 *
 * Both policies are evaluated FRESH here, never trusting a historical
 * `decision` value from the request log: the log's own decisions may reflect
 * an older policy.yaml that was active when each row was recorded (the proxy
 * loads policy once at startup, so a hand-edited file without a restart would
 * make historical rows stale relative to today's file). Pure and synchronous,
 * same posture as policy/evaluate.ts.
 */
import { evaluate } from "./evaluate.ts";
import type { CompiledPolicy } from "./compile.ts";
import type { Decision } from "./types.ts";

export interface DiffPair {
  readonly tool: string;
  readonly action: string;
}

export interface DiffEntry {
  readonly tool: string;
  readonly action: string;
  readonly from: Decision;
  readonly to: Decision;
}

export function diffPolicies(
  current: CompiledPolicy,
  candidate: CompiledPolicy,
  pairs: readonly DiffPair[],
): readonly DiffEntry[] {
  const entries: DiffEntry[] = [];
  for (const { tool, action } of pairs) {
    // Reachability mode: the log aggregate these pairs come from has no target
    // dimension, so "could this ever happen" is the only honest comparison.
    const from = evaluate(current, { tool, action, target: null }).decision;
    const to = evaluate(candidate, { tool, action, target: null }).decision;
    if (from !== to) entries.push({ tool, action, from, to });
  }
  return entries;
}
