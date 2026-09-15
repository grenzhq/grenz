/**
 * In-memory divergence aggregation for the shadow-policy canary.
 *
 * A candidate policy is evaluated (pure engine) alongside the enforced live
 * policy; every request is `observe`d and, where the two verdicts differ, the
 * `(tool, action, live, candidate)` divergence is counted. Aggregate metadata
 * only — no targets, bodies, or credential material — and no persistence: a
 * restart clears it (invariant 5; the operator runs the canary with the proxy
 * up). Modeled on `FlowFactStore`: no I/O, memory bounded by a distinct-key cap.
 */
import type { Decision } from "../policy/types.ts";

export type CanaryDirection = "stricter" | "looser";

export interface CanaryDivergence {
  readonly tool: string;
  readonly action: string;
  readonly live: Decision;
  readonly candidate: Decision;
  readonly direction: CanaryDirection;
  readonly count: number;
}

export interface CanarySnapshot {
  readonly requests: number;
  readonly divergences: number;
  readonly rows: readonly CanaryDivergence[];
}

/** Permissiveness order: a higher rank is MORE restrictive. */
const RANK: Record<Decision, number> = { allow: 0, require_approval: 1, deny: 2 };

/** Bounds memory: distinct diverging keys past this are dropped (not counted). */
const DEFAULT_MAX_KEYS = 2000;

interface Cell {
  readonly tool: string;
  readonly action: string;
  readonly live: Decision;
  readonly candidate: Decision;
  count: number;
}

export class CanaryStore {
  private requests = 0;
  private divergences = 0;
  private readonly cells = new Map<string, Cell>();
  constructor(private readonly maxKeys: number = DEFAULT_MAX_KEYS) {}

  observe(tool: string, action: string, live: Decision, candidate: Decision): void {
    this.requests += 1;
    if (live === candidate) return;
    this.divergences += 1;
    const key = `${tool} ${action} ${live} ${candidate}`;
    const existing = this.cells.get(key);
    if (existing) {
      existing.count += 1;
      return;
    }
    if (this.cells.size >= this.maxKeys) return; // bounded; excess key ignored
    this.cells.set(key, { tool, action, live, candidate, count: 1 });
  }

  snapshot(): CanarySnapshot {
    const rows: CanaryDivergence[] = [...this.cells.values()]
      .map((c) => ({
        tool: c.tool,
        action: c.action,
        live: c.live,
        candidate: c.candidate,
        direction: (RANK[c.candidate] > RANK[c.live] ? "stricter" : "looser") as CanaryDirection,
        count: c.count,
      }))
      .sort((a, b) => {
        if (a.direction !== b.direction) return a.direction === "stricter" ? -1 : 1;
        if (a.count !== b.count) return b.count - a.count;
        if (a.tool !== b.tool) return a.tool < b.tool ? -1 : 1;
        return a.action < b.action ? -1 : a.action > b.action ? 1 : 0;
      });
    return { requests: this.requests, divergences: this.divergences, rows };
  }
}
