/**
 * Session pin-fact store — an ephemeral, in-memory record of the target UNITS a
 * token-holder has established (with an allowed, forwarded action) per pin rule,
 * so the pin gate can tell whether a later request pivots to a new target.
 *
 * In-memory only, size-capped, no persistence: a proxy restart (or --watch
 * reload) clears it. Holds only log-safe strings the request already carries
 * (the extracted pin unit) — never a body or credential. NOT an audit trail: it
 * is pre-action state, truncatable and lossy by design.
 */
export interface PinFact {
  readonly ruleIndex: number;
  readonly unit: string;
  readonly ts: number;
}

export const DEFAULT_MAX_PER_KEY = 256;

export class PinStore {
  private readonly byKey = new Map<string, PinFact[]>();

  constructor(private readonly maxPerKey: number = DEFAULT_MAX_PER_KEY) {}

  record(key: string, ruleIndex: number, unit: string, now: number): void {
    let facts = this.byKey.get(key);
    if (!facts) {
      facts = [];
      this.byKey.set(key, facts);
    }
    facts.push({ ruleIndex, unit, ts: now });
    if (facts.length > this.maxPerKey) facts.splice(0, facts.length - this.maxPerKey);
  }

  /** Facts with ts >= sinceMs for this key. A pure read — never mutates the
   *  store, so callers may query different windows without discarding facts a
   *  wider query would want. Memory is bounded by the per-key cap alone. */
  factsSince(key: string, sinceMs: number): readonly PinFact[] {
    const facts = this.byKey.get(key);
    if (!facts) return [];
    return facts.filter((f) => f.ts >= sinceMs);
  }
}
