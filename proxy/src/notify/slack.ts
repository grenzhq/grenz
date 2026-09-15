/**
 * Slack notifier — posts to an Incoming Webhook when an approval is pending.
 *
 * This is a one-way push (notification). The decision itself is made through the
 * loopback admin API (`grenz approve|deny` or the console); interactive Slack
 * buttons need a public callback and belong to the later team plane. The webhook
 * URL is itself a secret and lives in the vault (key `slack_webhook`) — it is
 * never logged, and the message body carries no credential.
 */
import type { Notifier } from "./notifier.ts";
import type { ApprovalRecord, ApprovalOutcome } from "../approvals/broker.ts";

const NOTIFY_TIMEOUT_MS = 4000;

export class SlackNotifier implements Notifier {
  constructor(
    private readonly webhookUrl: string,
    private readonly emit: (line: string) => void = () => {},
  ) {}

  async approvalRequested(record: ApprovalRecord, approveHint: string): Promise<void> {
    const ttlSeconds = Math.max(0, Math.round((record.expiresAt - record.requestedAt) / 1000));
    // The operator's require_approval note (if any), shown to help the approver decide.
    const contextLine = record.context ? `_${record.context}_\n` : "";
    // Dual-control: tell approvers how many DISTINCT people must approve.
    const quorumLine = record.quorum > 1 ? `Needs *${record.quorum} distinct approvers*.\n` : "";
    const text =
      `:lock: *Grenz approval needed*\n` +
      `Agent \`${record.agentId}\` wants *${record.action}* on \`${record.tool}\` — \`${record.target}\`.\n` +
      quorumLine +
      contextLine +
      `Approve within ${ttlSeconds}s:  \`${approveHint}\`  (or deny with \`grenz deny ${record.id}\`).`;
    await this.post(text, record.id);
  }

  async approvalResolved(record: ApprovalRecord, outcome: ApprovalOutcome): Promise<void> {
    const who = outcome.decidedBy ?? "?";
    const line =
      outcome.state === "approved"
        ? `:white_check_mark: Approved by ${who}`
        : outcome.state === "denied"
          ? `:no_entry: Denied by ${who}`
          : outcome.state === "abandoned"
            ? `:ghost: Withdrawn (requester disconnected)`
            : `:hourglass: Expired (no decision)`;
    await this.post(`${line} — *${record.action}* on \`${record.tool}\` (${record.id}).`, record.id);
  }

  async tripwireTripped(
    agentId: string,
    action: string,
    target: string | null,
    note: string | null,
  ): Promise<void> {
    const where = target ? ` on \`${target}\`` : "";
    const why = note ? ` — ${note}` : "";
    await this.post(
      `:rotating_light: Tripwire: \`${agentId}\` attempted *${action}*${where} — revoked${why}.`,
      `tripwire:${agentId}`,
    );
  }

  async decoyTripped(
    kind: "token" | "upstream",
    actorId: string,
    upstreamName: string,
    path: string,
  ): Promise<void> {
    const what =
      kind === "token" ? `presented a decoy token` : `touched decoy upstream \`${upstreamName}\``;
    await this.post(
      `:rotating_light: Decoy tripped: \`${actorId}\` ${what} (\`${path}\`) — revoked.`,
      `decoy:${actorId}`,
    );
  }

  /** POST a message to the webhook. Never throws and never echoes the webhook
   *  URL (it is a secret) — a notification failure must not break the flow. */
  async breakGlassPulled(
    agentId: string,
    actions: readonly string[],
    pulledBy: string,
    reason: string,
    expiresAt: number,
  ): Promise<void> {
    const why = reason ? `, reason "${reason}"` : "";
    await this.post(
      `:rotating_light: *Break-glass pulled* by \`${pulledBy}\` for \`${agentId}\` — actions ` +
        `\`${actions.join(", ")}\`${why} (expires <t:${Math.floor(expiresAt / 1000)}:R>).`,
      `break-glass:${agentId}`,
    );
  }

  private async post(text: string, id: string): Promise<void> {
    try {
      const res = await fetch(this.webhookUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text }),
        signal: AbortSignal.timeout(NOTIFY_TIMEOUT_MS),
      });
      if (!res.ok) this.emit(`[notify] slack webhook returned ${res.status} for ${id}`);
    } catch {
      this.emit(`[notify] slack notification failed for ${id}`);
    }
  }
}
