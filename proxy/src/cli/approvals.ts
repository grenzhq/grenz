/**
 * `grenz approvals | approve <id> | deny <id> | status`
 *
 * Thin clients over the running proxy's loopback admin API. The pending-approval
 * state lives in the proxy (it holds the blocked request), so these commands
 * talk to it over HTTP using the local admin token.
 */
import { adminClient, callAdmin as call } from "./admin-client.ts";
import { flagString, type ParsedArgs } from "./args.ts";
import type { ApprovalRecord } from "../approvals/broker.ts";

export function fmtApproval(a: ApprovalRecord): string {
  const secs = Math.max(0, Math.round((a.expiresAt - Date.now()) / 1000));
  // Dual-control progress: distinct approvers so far / required.
  const q = a.quorum > 1 ? `  [${a.approvedBy.length}/${a.quorum} approved]` : "";
  const head = `  ${a.id}  ${a.agentId}  ${a.tool}:${a.action}  ${a.target}${q}  (expires ${secs}s)`;
  // The operator's require_approval note, on its own indented line for the human.
  return a.context ? `${head}\n         ↳ ${a.context}` : head;
}

export async function runApprovals(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await call(client, "GET", "/console/approvals");
  if (!res) return 1;
  const approvals = (res.body as { approvals?: ApprovalRecord[] }).approvals ?? [];
  if (approvals.length === 0) {
    process.stdout.write("no pending approvals\n");
    return 0;
  }
  process.stdout.write(`pending approvals (${approvals.length}):\n`);
  for (const a of approvals) process.stdout.write(fmtApproval(a) + "\n");
  return 0;
}

async function decide(args: ParsedArgs, action: "approve" | "deny"): Promise<number> {
  const id = args.positionals[0];
  if (!id) {
    process.stderr.write(`grenz: usage: grenz ${action} <id>\n`);
    return 1;
  }
  // `--as` is deprecated: the approver is now the AUTHENTICATED admin token
  // (server-derived), which is what makes quorum a real separation-of-duties
  // control. A supplied label is ignored.
  const asLabel = flagString(args, "as");
  if (asLabel) {
    process.stderr.write(
      `grenz: --as is deprecated — the approver is now the authenticated admin token; ignoring "${asLabel}"\n`,
    );
  }
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await call(client, "POST", `/console/approvals/${encodeURIComponent(id)}/${action}`, {
    body: {},
  });
  if (!res) return 1;
  if (res.status === 200) {
    // The recorded approver is echoed by the proxy (the token's name).
    const by = (res.body as { by?: string }).by ?? "you";
    if (action === "deny") {
      process.stdout.write(`denied ${id} (as ${by})\n`);
      return 0;
    }
    const b = res.body as { satisfied?: boolean; approvals?: number; quorum?: number };
    if (b.satisfied === false && (b.quorum ?? 1) > 1) {
      const remaining = (b.quorum ?? 1) - (b.approvals ?? 0);
      process.stdout.write(
        `recorded your approval as ${by} — ${b.approvals}/${b.quorum}, waiting for ${remaining} more\n`,
      );
    } else {
      process.stdout.write(`approved ${id} (as ${by})\n`);
    }
    return 0;
  }
  const reason = (res.body as { error?: string }).error ?? `http ${res.status}`;
  process.stderr.write(`grenz: could not ${action} ${id}: ${reason}\n`);
  return 1;
}

export function runApprove(args: ParsedArgs): Promise<number> {
  return decide(args, "approve");
}

export function runDeny(args: ParsedArgs): Promise<number> {
  return decide(args, "deny");
}

export async function runStatus(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await call(client, "GET", "/console/summary");
  if (!res) return 1;
  const s = res.body as Record<string, number>;
  process.stdout.write(
    [
      `Grenz — last ${s.window_hours ?? 24}h`,
      `  requests:  ${s.total ?? 0}`,
      `  allows:    ${s.allow ?? 0}`,
      `  denies:    ${s.deny ?? 0}`,
      `  approvals: ${s.approvalGranted ?? 0} granted, ${s.approvalDenied ?? 0} denied, ${s.approvalExpired ?? 0} expired`,
      `  pending:   ${s.pending ?? 0}`,
    ].join("\n") + "\n",
  );
  return 0;
}
