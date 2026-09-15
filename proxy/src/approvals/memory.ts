/**
 * Approval memory — a short-lived record of recent HUMAN decisions.
 *
 * When enabled (approvals.remember_seconds > 0), a human's approve/deny for an
 * exact (agent, tool, action, target) is remembered for the window, so an
 * identical retry resolves instantly instead of re-prompting. Both directions
 * are remembered: a sticky deny closes the retry-until-a-tired-human-clicks-
 * wrong loop. Expiries are NEVER remembered — only a real decision is.
 *
 * In-memory only, size-capped, no persistence: a proxy restart (or a --watch
 * policy reload) clears it. Keys and values hold only the log-safe strings the
 * approval record already carries — never a request body or credential.
 */

export type RememberedOutcome = "approved" | "denied";

/** The exact identity a decision is remembered under. */
export interface MemoryKeyInput {
  readonly agentId: string;
  readonly tool: string;
  readonly action: string;
  readonly target: string;
}

export const MAX_ENTRIES = 1000;

interface Entry {
  readonly outcome: RememberedOutcome;
  readonly expiresAt: number;
}

export class ApprovalMemory {
  private readonly entries = new Map<string, Entry>();

  constructor(
    public readonly ttlMs: number,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** NUL separator: it cannot appear in these strings, so crafted values
   *  cannot collide keys the way a printable separator could. */
  private static key(input: MemoryKeyInput): string {
    return [input.agentId, input.tool, input.action, input.target].join("\u0000");
  }

  /** Store a human decision. Refreshes the window on re-remember. */
  remember(input: MemoryKeyInput, outcome: RememberedOutcome): void {
    if (this.ttlMs <= 0) return;
    const key = ApprovalMemory.key(input);
    this.entries.delete(key); // re-insert to refresh eviction order
    this.entries.set(key, { outcome, expiresAt: this.clock() + this.ttlMs });
    if (this.entries.size > MAX_ENTRIES) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
  }

  /** The live remembered outcome, or null. Expired entries are swept on read. */
  recall(input: MemoryKeyInput): RememberedOutcome | null {
    const key = ApprovalMemory.key(input);
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.clock()) {
      this.entries.delete(key);
      return null;
    }
    return entry.outcome;
  }

  /** Drop everything (policy reload / shutdown). */
  clear(): void {
    this.entries.clear();
  }

  size(): number {
    return this.entries.size;
  }
}
