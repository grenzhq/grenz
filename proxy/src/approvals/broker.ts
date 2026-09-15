/**
 * In-proxy approval broker.
 *
 * When a request resolves to `require_approval`, the pipeline BLOCKS on a
 * pending approval created here. A human decides via the loopback admin API
 * (`grenz approve|deny`, or the console). If nobody decides within the TTL,
 * the approval expires and the request is DENIED (invariant 4: expire → DENY).
 *
 * State is in-memory and lives only for the life of the held request. There is
 * no persistence and no secret material here — an approval references the
 * action being gated, never a credential.
 */
import { shortId } from "../util/id.ts";

export type ApprovalState = "pending" | "approved" | "denied" | "expired" | "abandoned";

export interface ApprovalInput {
  readonly agentId: string;
  readonly upstream: string;
  readonly tool: string;
  readonly action: string;
  readonly target: string;
  readonly method: string;
  /** Optional operator-authored note from a require_approval rule's `message`,
   *  shown to the human approver. Static policy text (log-safe); ephemeral —
   *  lives only in this in-memory record, never written to the request log. */
  readonly context?: string;
}

export interface ApprovalRecord extends ApprovalInput {
  readonly id: string;
  readonly requestedAt: number;
  readonly expiresAt: number;
  state: ApprovalState;
  decidedBy: string | null;
  /** DISTINCT human approvers required before this settles approved. Default 1. */
  readonly quorum: number;
  /** Distinct approver labels recorded so far (in-memory only, never logged). */
  approvedBy: string[];
}

export interface ApprovalOutcome {
  readonly state: "approved" | "denied" | "expired" | "abandoned";
  readonly decidedBy: string | null;
}

/** The result of an `approveBy` — a partial approve is neither a settle nor a
 *  404, so the caller (console/CLI) can report N/quorum progress accurately. */
export interface ApproveResult {
  readonly status: "settled" | "recorded" | "duplicate" | "not_found";
  /** Distinct approvers recorded so far. */
  readonly approvals: number;
  readonly quorum: number;
}

interface Entry {
  readonly record: ApprovalRecord;
  readonly resolve: (o: ApprovalOutcome) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

export class ApprovalBroker {
  private readonly entries = new Map<string, Entry>();

  constructor(
    public readonly ttlMs: number,
    /** Hard cap on concurrent pending approvals — bounds held sockets/timers. */
    public readonly maxPending: number = 1000,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** True when no more pending approvals can be accepted (resource guard). */
  atCapacity(): boolean {
    return this.entries.size >= this.maxPending;
  }

  /** Create a pending approval and return a promise that settles when decided/expired.
   *  `quorum` is the number of DISTINCT approvers required (default 1). */
  create(input: ApprovalInput, quorum = 1): { id: string; wait: Promise<ApprovalOutcome> } {
    const now = this.clock();
    const id = shortId("apr");
    const record: ApprovalRecord = {
      ...input,
      id,
      requestedAt: now,
      expiresAt: now + this.ttlMs,
      state: "pending",
      decidedBy: null,
      quorum: Math.max(1, quorum),
      approvedBy: [],
    };
    let resolve!: (o: ApprovalOutcome) => void;
    const wait = new Promise<ApprovalOutcome>((r) => {
      resolve = r;
    });
    const timer = setTimeout(() => this.settle(id, "expired", null), this.ttlMs);
    this.entries.set(id, { record, resolve, timer });
    return { id, wait };
  }

  private settle(id: string, state: ApprovalOutcome["state"], decidedBy: string | null): boolean {
    const entry = this.entries.get(id);
    if (!entry || entry.record.state !== "pending") return false;
    clearTimeout(entry.timer);
    entry.record.state = state;
    entry.record.decidedBy = decidedBy;
    this.entries.delete(id);
    entry.resolve({ state, decidedBy });
    return true;
  }

  /**
   * Record a DISTINCT approver `by`. Settles the request approved only when the
   * distinct-approver count reaches the record's quorum; otherwise stays pending
   * (the TTL is NOT extended). Same approver twice counts once. The `status`
   * lets the caller report N/quorum progress instead of a bare boolean.
   */
  approveBy(id: string, by: string): ApproveResult {
    const entry = this.entries.get(id);
    if (!entry || entry.record.state !== "pending") {
      return { status: "not_found", approvals: 0, quorum: 0 };
    }
    const rec = entry.record;
    const duplicate = rec.approvedBy.includes(by);
    if (!duplicate) rec.approvedBy.push(by);
    if (rec.approvedBy.length >= rec.quorum) {
      this.settle(id, "approved", by); // `by` = the approver who reached quorum
      return { status: "settled", approvals: rec.approvedBy.length, quorum: rec.quorum };
    }
    return {
      status: duplicate ? "duplicate" : "recorded",
      approvals: rec.approvedBy.length,
      quorum: rec.quorum,
    };
  }

  /** Backward-compatible boolean approve: true iff this call SETTLED the request
   *  as approved (i.e. reached quorum). For the default quorum of 1, the first
   *  approve settles — byte-identical to the pre-quorum behavior. */
  approve(id: string, by: string): boolean {
    return this.approveBy(id, by).status === "settled";
  }

  deny(id: string, by: string): boolean {
    return this.settle(id, "denied", by);
  }

  /** Cancel a pending approval because its requester vanished (the client
   *  disconnected). Settles to "abandoned" — neither an approval nor a denial,
   *  so it is never remembered as a human decision. No-op if already settled. */
  cancel(id: string): boolean {
    return this.settle(id, "abandoned", null);
  }

  /** Snapshot of pending approvals, oldest first. `approvedBy` is copied by
   *  value so a caller can never mutate the live record. */
  list(): ApprovalRecord[] {
    return [...this.entries.values()]
      .map((e) => ({ ...e.record, approvedBy: [...e.record.approvedBy] }))
      .sort((a, b) => a.requestedAt - b.requestedAt);
  }

  get(id: string): ApprovalRecord | undefined {
    const entry = this.entries.get(id);
    return entry ? { ...entry.record, approvedBy: [...entry.record.approvedBy] } : undefined;
  }

  pendingCount(): number {
    return this.entries.size;
  }

  /** Expire everything (used on shutdown so held requests get a response). */
  drain(): void {
    for (const id of [...this.entries.keys()]) this.settle(id, "expired", null);
  }
}
