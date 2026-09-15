/**
 * Pure planning for `grenz policy rollback`. Given the current policy text, a
 * candidate (a past snapshot), and the (tool, action) pairs seen in history,
 * decide whether the rollback can proceed and what decisions would change.
 *
 * Fail-closed: a candidate that will not compile is refused — the proxy must
 * never be handed a policy it could not load. No IO; the caller does the file
 * writes.
 */
import { compilePolicyYaml } from "./compile.ts";
import { diffPolicies, type DiffPair, type DiffEntry } from "./diff.ts";

export type RollbackPlan =
  | { readonly ok: false; readonly reason: string }
  | { readonly ok: true; readonly currentCompiles: boolean; readonly diff: readonly DiffEntry[] };

export function planRollback(
  currentText: string,
  candidateText: string,
  pairs: readonly DiffPair[],
): RollbackPlan {
  const candidate = compilePolicyYaml(candidateText);
  if (!candidate.ok) {
    return { ok: false, reason: `snapshot will not compile: ${candidate.error}` };
  }
  const current = compilePolicyYaml(currentText);
  if (!current.ok) {
    return { ok: true, currentCompiles: false, diff: [] };
  }
  return {
    ok: true,
    currentCompiles: true,
    diff: diffPolicies(current.policy, candidate.policy, pairs),
  };
}
