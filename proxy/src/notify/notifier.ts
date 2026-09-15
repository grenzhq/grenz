/**
 * Notifier interface — how Grenz pushes an approval request to a human.
 *
 * Behind an interface so Slack, and later other channels, slot in without
 * touching the pipeline. A notification carries only the action being gated and
 * how to approve it — never a credential.
 */
import type { ApprovalRecord, ApprovalOutcome } from "../approvals/broker.ts";

export interface Notifier {
  /** Announce that an approval is pending. Must never throw into the pipeline. */
  approvalRequested(record: ApprovalRecord, approveHint: string): Promise<void>;
  /** Announce that a pending approval settled (approved / denied / expired /
   *  abandoned), so the channel's prompt is visibly closed. Optional; fired
   *  best-effort and must never throw into the pipeline. */
  approvalResolved?(record: ApprovalRecord, outcome: ApprovalOutcome): Promise<void>;
  /** Announce that a tripwire fired and the actor was revoked. Optional; fired
   *  best-effort and must never throw into the pipeline. */
  tripwireTripped?(agentId: string, action: string, target: string | null, note: string | null): Promise<void>;
  /** Announce that a decoy was touched and the toucher was revoked. Optional;
   *  fired best-effort and must never throw into the pipeline. Carries ids,
   *  names, and a path — never a token value or credential. */
  decoyTripped?(
    kind: "token" | "upstream",
    actorId: string,
    upstreamName: string,
    path: string,
  ): Promise<void>;
  /** Announce that a known agent's token arrived on the ADMIN listener while the
   *  proxy is in socket mode — either a misconfigured agent or a stolen token
   *  being replayed. Fired once per agent id per process. Optional; best-effort,
   *  must never throw into the pipeline. Carries ids, a name and a path — never
   *  a token value or credential. */
  wrongListener?(actorId: string, upstreamName: string, path: string): Promise<void>;
  /** Announce that an admin pulled break-glass (a denied action was unlocked for
   *  approval). Optional; best-effort, must never throw into the pipeline. */
  breakGlassPulled?(
    agentId: string,
    actions: readonly string[],
    pulledBy: string,
    reason: string,
    expiresAt: number,
  ): Promise<void>;
}

/** Default no-op notifier when no channel is configured. */
export const nullNotifier: Notifier = {
  async approvalRequested(): Promise<void> {
    /* no channel configured */
  },
  async approvalResolved(): Promise<void> {
    /* no channel configured */
  },
  async tripwireTripped(): Promise<void> {
    /* no channel configured */
  },
  async decoyTripped(): Promise<void> {
    /* no channel configured */
  },
  async wrongListener(): Promise<void> {
    /* no channel configured */
  },
};
