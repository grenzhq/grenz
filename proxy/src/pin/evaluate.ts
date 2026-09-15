/**
 * Pure pin evaluator. Given a session's pin facts, decides whether the current
 * (action, target) pivots to a NEW target unit under any pin rule — the lateral-
 * movement signal. No I/O; the proxy-layer gate in dispatch() wraps this.
 *
 * Core rule: a rule escalates iff the session has ALREADY pinned some unit under
 * it (within the window) AND the current unit is not among them. The first
 * matching action on a fresh session is free — it defines the pin.
 */
import type { CompiledPin } from "../policy/compile.ts";
import type { PinFact } from "./store.ts";

export interface PinHit {
  readonly effect: "require_approval" | "deny";
  readonly ruleIndex: number;
  readonly unit: string;
}

export function maxWithinMs(pins: readonly CompiledPin[]): number {
  let m = 0;
  for (const p of pins) if (p.withinMs > m) m = p.withinMs;
  return m;
}

export function evaluatePin(
  pins: readonly CompiledPin[],
  facts: readonly PinFact[],
  action: string,
  target: string,
  now: number,
): PinHit | null {
  let best: PinHit | null = null;
  for (let i = 0; i < pins.length; i++) {
    const rule = pins[i]!;
    if (!rule.on.some((p) => p.re.test(action))) continue;
    const m = rule.key.exec(target);
    const unit = m?.[1];
    if (!unit) continue; // pin-inert: cannot identify a unit
    const sinceMs = now - rule.withinMs;
    const pinned = new Set<string>();
    for (const f of facts) {
      if (f.ruleIndex === i && f.ts >= sinceMs) pinned.add(f.unit);
    }
    if (pinned.size > 0 && !pinned.has(unit)) {
      const hit: PinHit = { effect: rule.effect, ruleIndex: i, unit };
      // Prefer deny over require_approval; on equal effect the lowest-index rule
      // wins (best is only replaced when upgrading to a deny).
      if (!best || (best.effect !== "deny" && hit.effect === "deny")) best = hit;
    }
  }
  return best;
}

/** One (action, target) pair from a request — an MCP batch carries several. */
export interface ActionTarget {
  readonly action: string;
  readonly target: string;
}

/** A pin a single (action, target) ESTABLISHES: which rule, and which unit. */
export interface PinUnit {
  readonly ruleIndex: number;
  readonly unit: string;
}

/**
 * Every (rule, unit) this (action, target) establishes. Pure. Shared by the
 * gate below (which folds a batch's own units in as it walks it) and by the
 * proxy's post-forward fact seeding, so the two can never drift.
 */
export function pinUnitsFor(
  pins: readonly CompiledPin[],
  action: string,
  target: string,
): readonly PinUnit[] {
  const out: PinUnit[] = [];
  for (let i = 0; i < pins.length; i++) {
    const rule = pins[i]!;
    if (!rule.on.some((p) => p.re.test(action))) continue;
    const m = rule.key.exec(target);
    if (m?.[1]) out.push({ ruleIndex: i, unit: m[1] });
  }
  return out;
}

/**
 * Pin evaluation over a whole request's pairs (an MCP batch is several). Pure.
 *
 * Each pair is measured against the stored facts PLUS the units the earlier
 * pairs in this same request establish — so a batch that pivots inside itself
 * (`alpha` then `beta` in one POST) escalates exactly as the two sequential
 * requests would. Without that fold a batch is a free lateral move.
 *
 * Returns the strongest hit (deny beats require_approval), or null.
 */
export function evaluatePinBatch(
  pins: readonly CompiledPin[],
  facts: readonly PinFact[],
  pairs: readonly ActionTarget[],
  now: number,
): PinHit | null {
  let best: PinHit | null = null;
  const seen: PinFact[] = [...facts];
  for (const { action, target } of pairs) {
    const hit = evaluatePin(pins, seen, action, target, now);
    if (hit && (best === null || (best.effect !== "deny" && hit.effect === "deny"))) best = hit;
    for (const u of pinUnitsFor(pins, action, target)) {
      seen.push({ ruleIndex: u.ruleIndex, unit: u.unit, ts: now });
    }
  }
  return best;
}
