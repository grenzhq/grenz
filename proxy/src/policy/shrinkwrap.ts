/**
 * Pure policy tightening: rewrite each grant's `allow` to exactly the actions
 * the agent actually used (from the request log), leaving every other field —
 * `deny`, `require_approval`, `targets`, budget, flows, tripwires, schedule —
 * untouched. Authoring FROM operational data; it only ever tightens (never
 * promotes an approval-gated or JIT action to a bare allow). Pure: given the
 * same source + used map it returns the same new source and never mutates input.
 */
import type { PolicySource } from "./schema.ts";

export function shrinkwrapPolicy(
  source: PolicySource,
  used: ReadonlyMap<string, ReadonlySet<string>>,
): PolicySource {
  const grants = source.grants.map((grant) => {
    const usedForTool = used.get(grant.tool) ?? new Set<string>();
    const allow = [...usedForTool].sort();
    return { ...grant, allow };
  });
  return { ...source, grants };
}
