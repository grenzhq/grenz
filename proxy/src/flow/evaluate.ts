/**
 * Pure taint-flow decision. Given the compiled flow rules, a snapshot of the
 * token-holder's recent SOURCE facts, the requested action, and `now`, decide
 * whether this action is a SINK completing a gated read->write sequence.
 *
 * Deterministic: no clock read, no I/O — `now` and `facts` are inputs. The
 * proxy layer owns fact accumulation and the escalation; this is the comparator.
 */
import type { CompiledFlow } from "../policy/compile.ts";
import type { FlowFact } from "./facts.ts";

export interface FlowHit {
  readonly effect: "deny" | "require_approval";
  readonly flowIndex: number;
  readonly source: { readonly action: string; readonly target: string | null };
}

export function maxWithinMs(flows: readonly CompiledFlow[]): number {
  let max = 0;
  for (const f of flows) if (f.withinMs > max) max = f.withinMs;
  return max;
}

export function evaluateFlows(
  flows: readonly CompiledFlow[],
  facts: readonly FlowFact[],
  action: string,
  now: number,
): FlowHit | null {
  let best: FlowHit | null = null;
  for (let i = 0; i < flows.length; i++) {
    const flow = flows[i]!;
    if (!flow.then.some((p) => p.re.test(action))) continue;
    const since = now - flow.withinMs;
    // Most-recent qualifying source, for context display.
    let source: FlowFact | null = null;
    for (const fact of facts) {
      if (fact.ts < since) continue;
      if (!flow.when.some((p) => p.re.test(fact.action))) continue;
      if (source === null || fact.ts > source.ts) source = fact;
    }
    if (source === null) continue;
    const hit: FlowHit = {
      effect: flow.effect,
      flowIndex: i,
      source: { action: source.action, target: source.target },
    };
    // Strongest effect wins (deny > require_approval); ties keep the earliest.
    if (best === null || (hit.effect === "deny" && best.effect !== "deny")) best = hit;
  }
  return best;
}

/** One (action, target) pair from a request — an MCP batch carries several. */
export interface FlowPair {
  readonly action: string;
  readonly target: string;
}

/**
 * Flow evaluation over a whole request's pairs (an MCP batch is several). Pure.
 *
 * Each pair is measured against the stored facts PLUS the SOURCE facts the
 * earlier pairs in this same request would seed — so a batch that carries both
 * halves of a read→exfil sequence is gated exactly as the two sequential
 * requests would be. Without that fold, batching is a free bypass.
 *
 * Returns the strongest hit (deny beats require_approval) together with the
 * sink action that produced it, or null.
 */
export function evaluateFlowsBatch(
  flows: readonly CompiledFlow[],
  facts: readonly FlowFact[],
  pairs: readonly FlowPair[],
  now: number,
): { readonly hit: FlowHit; readonly action: string } | null {
  let best: { hit: FlowHit; action: string } | null = null;
  const seen: FlowFact[] = [...facts];
  for (const { action, target } of pairs) {
    const hit = evaluateFlows(flows, seen, action, now);
    if (hit && (best === null || (hit.effect === "deny" && best.hit.effect !== "deny"))) {
      best = { hit, action };
    }
    if (flows.some((f) => f.when.some((p) => p.re.test(action)))) {
      seen.push({ action, target, ts: now });
    }
  }
  return best;
}
