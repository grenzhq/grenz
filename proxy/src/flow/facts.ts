/**
 * Taint-flow fact store — an ephemeral, in-memory record of the (allowed,
 * forwarded) SOURCE actions a token-holder has taken, so the flow gate can tell
 * whether a SINK request completes a gated read->write sequence.
 *
 * In-memory only, size-capped, no persistence: a proxy restart (or --watch
 * reload) clears it. Holds only log-safe strings the request already carries
 * (action, target) — never a body or credential. NOT an audit trail: it is
 * pre-action state, truncatable and lossy by design.
 */
export interface FlowFact {
  readonly action: string;
  readonly target: string | null;
  readonly ts: number;
}

export const DEFAULT_MAX_PER_KEY = 256;

export class FlowFactStore {
  private readonly byKey = new Map<string, FlowFact[]>();

  constructor(private readonly maxPerKey: number = DEFAULT_MAX_PER_KEY) {}

  record(key: string, action: string, target: string | null, now: number): void {
    let facts = this.byKey.get(key);
    if (!facts) {
      facts = [];
      this.byKey.set(key, facts);
    }
    facts.push({ action, target, ts: now });
    if (facts.length > this.maxPerKey) facts.splice(0, facts.length - this.maxPerKey);
  }

  /** Facts with ts >= sinceMs for this key. A pure read — it never mutates the
   *  store, so callers may query different windows without discarding facts a
   *  wider query would want. Memory is bounded by the per-key cap alone. */
  factsSince(key: string, sinceMs: number): readonly FlowFact[] {
    const facts = this.byKey.get(key);
    if (!facts) return [];
    return facts.filter((f) => f.ts >= sinceMs);
  }
}
