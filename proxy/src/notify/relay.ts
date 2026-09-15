/**
 * Relay notifier — the outbound-only approval return path for a headless proxy
 * on a firewalled runner.
 *
 * `approvalRequested` POSTs the pending action as METADATA (never a credential,
 * token value, or request body) to the relay, then long-polls an outbound
 * endpoint for the verdict. A verdict settles the EXISTING ApprovalBroker via
 * the same approveBy/deny calls the admin CLI uses, so the broker stays the sole
 * authority on clock/TTL/deny (invariant 4). A create failure, an unreachable
 * relay, or a malformed verdict never approves — the broker's TTL denies.
 */
import type { Notifier } from "./notifier.ts";
import type { ApprovalRecord, ApprovalOutcome, ApproveResult } from "../approvals/broker.ts";

/** Narrow view of the broker: RelayChannel may only settle, never create/list. */
export interface RelayBrokerHandle {
  approveBy(id: string, by: string): ApproveResult;
  deny(id: string, by: string): boolean;
}

export interface RelayOptions {
  readonly url: string;
  readonly token: string;
  readonly pollWindowMs?: number;
  /** Backoff between reconnect windows. A correct relay long-polls for
   *  ~pollWindowMs, but a relay that answers `pending` instantly would
   *  otherwise be hammered in a hot loop — this bounds the reconnect rate. */
  readonly reconnectDelayMs?: number;
  readonly fetchImpl?: typeof fetch;
  readonly clock?: () => number;
  readonly emit?: (line: string) => void;
}

interface RelayVerdict {
  status: "pending" | "approved" | "denied" | "expired";
  resolved_by?: string;
}

const DEFAULT_POLL_WINDOW_MS = 25_000;
const POLL_TIMEOUT_SLACK_MS = 5_000;
const CREATE_TIMEOUT_MS = 4_000;
const DEFAULT_RECONNECT_DELAY_MS = 1_000;

export class RelayChannel implements Notifier {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly pollWindowMs: number;
  private readonly reconnectDelayMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly clock: () => number;
  private readonly emit: (line: string) => void;
  /** In-flight poll loops keyed by approval id, so a resolution can abort them. */
  private readonly polls = new Map<string, AbortController>();

  constructor(opts: RelayOptions, private readonly broker: RelayBrokerHandle) {
    this.baseUrl = opts.url.replace(/\/+$/, "");
    this.token = opts.token;
    this.pollWindowMs = opts.pollWindowMs ?? DEFAULT_POLL_WINDOW_MS;
    this.reconnectDelayMs = opts.reconnectDelayMs ?? DEFAULT_RECONNECT_DELAY_MS;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.clock = opts.clock ?? ((): number => Date.now());
    this.emit = opts.emit ?? ((): void => {});
  }

  async approvalRequested(record: ApprovalRecord, _approveHint: string): Promise<void> {
    const created = await this.create(record);
    if (!created) return; // fail-closed: no poll, no settle → the broker's TTL denies
    const ctrl = new AbortController();
    this.polls.set(record.id, ctrl);
    // Background: not awaited. The pipeline blocks on broker.wait, which the loop
    // settles. Clean up the registry when the loop ends (unless already replaced).
    void this.pollLoop(record, ctrl.signal).finally(() => {
      if (this.polls.get(record.id) === ctrl) this.polls.delete(record.id);
    });
  }

  async approvalResolved(record: ApprovalRecord, outcome: ApprovalOutcome): Promise<void> {
    const ctrl = this.polls.get(record.id);
    if (ctrl) {
      ctrl.abort();
      this.polls.delete(record.id);
    }
    // Best-effort: tell the relay the final state so it can close the Slack
    // message. Never throws into the pipeline.
    try {
      await this.fetchImpl(`${this.baseUrl}/v1/approvals/${record.id}/resolution`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({ status: outcome.state }),
        signal: AbortSignal.timeout(CREATE_TIMEOUT_MS),
      });
    } catch {
      this.emit(`[relay] resolution post failed for ${record.id} (ignored)`);
    }
  }

  async tripwireTripped(
    agentId: string,
    action: string,
    target: string | null,
    note: string | null,
  ): Promise<void> {
    // The whole point of the headless deployment: a trip-and-cascade alarm has to
    // reach the remote operator over the SAME outbound path as approvals, since
    // the runner can't be reached inbound. Fire-and-forget — there is no verdict
    // to poll; the revoke already happened locally.
    await this.postAlarm({ kind: "tripwire", agentId, action, target, note });
  }

  async decoyTripped(
    kind: "token" | "upstream",
    actorId: string,
    upstreamName: string,
    path: string,
  ): Promise<void> {
    await this.postAlarm({ kind: "decoy", decoy: kind, actorId, upstream: upstreamName, path });
  }

  /** POST a trip/decoy alarm as metadata. Best-effort: a failure to reach the
   *  relay never throws into the pipeline (the local revoke stands regardless).
   *  The body carries ids, names, an action/target, and a path — NEVER a token
   *  value, credential, or request body. */
  private async postAlarm(event: Record<string, unknown>): Promise<void> {
    try {
      await this.fetchImpl(`${this.baseUrl}/v1/alarms`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({ ...event, at: this.clock() }),
        signal: AbortSignal.timeout(CREATE_TIMEOUT_MS),
      });
    } catch {
      this.emit(`[relay] alarm post failed (${String(event.kind)}) (ignored; local revoke stands)`);
    }
  }

  /** POST the pending action as metadata. Returns false on any failure. */
  private async create(record: ApprovalRecord): Promise<boolean> {
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/v1/approvals`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(this.payload(record)),
        signal: AbortSignal.timeout(CREATE_TIMEOUT_MS),
      });
      if (!res.ok) {
        this.emit(`[relay] post failed for ${record.id} (${res.status}) (will expire→DENY)`);
        return false;
      }
      return true;
    } catch {
      this.emit(`[relay] post failed for ${record.id} (will expire→DENY)`);
      return false;
    }
  }

  /** Long-poll until a verdict lands or the record's local deadline passes.
   *  Reconnects each window so no single fetch approaches Bun's ~255s cap. */
  private async pollLoop(record: ApprovalRecord, signal: AbortSignal): Promise<void> {
    while (this.clock() < record.expiresAt && !signal.aborted) {
      let verdict: RelayVerdict | null;
      try {
        verdict = await this.pollOnce(record.id, signal);
      } catch {
        verdict = null; // timeout / network blip / abort → back off, then reconnect
      }
      if (verdict?.status === "approved") {
        this.broker.approveBy(record.id, verdict.resolved_by ?? "relay");
        return;
      }
      if (verdict?.status === "denied") {
        this.broker.deny(record.id, verdict.resolved_by ?? "relay");
        return;
      }
      // malformed / pending / expired / error → back off, then keep polling.
      // Never approve on ambiguity. The backoff bounds the reconnect rate (and
      // yields so an abort or the local deadline can end the loop promptly).
      await this.backoff(signal);
    }
  }

  /** Sleep reconnectDelayMs, resolving early if the poll is aborted. */
  private backoff(signal: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      if (this.reconnectDelayMs <= 0 || signal.aborted) {
        resolve();
        return;
      }
      const timer = setTimeout(resolve, this.reconnectDelayMs);
      signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
    });
  }

  /** One long-poll GET. Returns a validated verdict, or null (pending/malformed). */
  private async pollOnce(id: string, signal: AbortSignal): Promise<RelayVerdict | null> {
    const combined = AbortSignal.any([signal, AbortSignal.timeout(this.pollWindowMs + POLL_TIMEOUT_SLACK_MS)]);
    const res = await this.fetchImpl(`${this.baseUrl}/v1/approvals/${id}`, {
      method: "GET",
      headers: this.headers(),
      signal: combined,
    });
    if (!res.ok) return null;
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      return null;
    }
    return this.parseVerdict(body);
  }

  /** Validate the verdict shape. Unknown/missing status → null (treated pending). */
  private parseVerdict(body: unknown): RelayVerdict | null {
    if (typeof body !== "object" || body === null) return null;
    const rec = body as Record<string, unknown>;
    const status = rec.status;
    if (status !== "approved" && status !== "denied" && status !== "pending" && status !== "expired") {
      return null;
    }
    const rb = rec.resolved_by;
    return { status, resolved_by: typeof rb === "string" ? rb : undefined };
  }

  /** Metadata payload — the log-safe subset a human approver already sees.
   *  NEVER a credential, token value, or request body. */
  private payload(r: ApprovalRecord): Record<string, unknown> {
    return {
      id: r.id,
      agentId: r.agentId,
      upstream: r.upstream,
      tool: r.tool,
      action: r.action,
      target: r.target,
      method: r.method,
      context: r.context,
      requestedAt: r.requestedAt,
      expiresAt: r.expiresAt,
    };
  }

  private headers(): Record<string, string> {
    return { "content-type": "application/json", authorization: `Bearer ${this.token}` };
  }
}
