/**
 * Resolve the tightest response-size cap for a (action, target) from compiled
 * policy. Pure and synchronous — a read like `evaluate`, never on a network
 * path. Most-restrictive-wins: smallest max_bytes; ties broken toward `deny`.
 * A null target is reachability mode (a targeted rule matches) for explain/lint.
 */
import type { CompiledPolicy, CompiledResponseRule } from "../policy/compile.ts";

export interface ResolvedResponseLimit {
  readonly maxBytes: number;
  readonly onExceed: "truncate" | "deny";
}

function matches(rule: CompiledResponseRule, action: string, target: string | null): boolean {
  if (!rule.on.some((p) => p.re.test(action))) return false;
  if (rule.targets === null) return true;
  if (target === null) return true; // reachability: a targeted rule is reachable
  return rule.targets.some((p) => p.re.test(target));
}

/** The more restrictive of two limits: smaller cap wins; tie → deny. */
function tightest(a: ResolvedResponseLimit, b: ResolvedResponseLimit): ResolvedResponseLimit {
  if (b.maxBytes < a.maxBytes) return b;
  if (b.maxBytes > a.maxBytes) return a;
  return a.onExceed === "deny" ? a : b; // equal bytes: prefer deny
}

export function resolveResponseLimit(
  policy: CompiledPolicy,
  action: string,
  target: string | null,
): ResolvedResponseLimit | null {
  let best: ResolvedResponseLimit | null = null;
  for (const rule of policy.responses) {
    if (!matches(rule, action, target)) continue;
    const here: ResolvedResponseLimit = { maxBytes: rule.maxBytes, onExceed: rule.onExceed };
    best = best === null ? here : tightest(best, here);
  }
  return best;
}
