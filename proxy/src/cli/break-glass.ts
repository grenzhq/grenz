/**
 * `grenz break-glass <agent> --action <a,b> --reason "..." [--ttl <s>] [--quorum <n>]`
 * `grenz break-glass`   (list active windows)
 *
 * Break the glass in an emergency: unlock an otherwise-DENIED action for the
 * agent so it becomes approvable (a human still taps), for a bounded TTL, loudly
 * notified and attributed to your admin token. Requires a running `grenz run`
 * and an admin credential.
 *
 * To end a window early, use the kill-switch on its id:  grenz revoke <bg-id>
 *
 * This is operational emergency access, NOT an audit trail.
 */
import { adminClient, callAdmin } from "./admin-client.ts";
import { flagString, type ParsedArgs } from "./args.ts";

interface WindowRow {
  readonly id: string;
  readonly agent: string;
  readonly actions: readonly string[];
  readonly quorum: number;
  readonly reason: string;
  readonly pulled_by: string;
  readonly expires_at: number;
}

/** Pure formatter for the active-window list. */
export function renderWindows(rows: readonly WindowRow[]): string {
  if (rows.length === 0) return "no active break-glass windows";
  const lines = [`active break-glass windows (${rows.length}):`];
  for (const w of rows) {
    const expires = new Date(w.expires_at).toISOString();
    const reason = w.reason ? `  "${w.reason}"` : "";
    lines.push(
      `  ${w.id}  ${w.agent.padEnd(14)} q${w.quorum} by ${w.pulled_by.padEnd(12)} ` +
        `${w.actions.join(",")}  expires ${expires}${reason}`,
    );
  }
  return lines.join("\n");
}

async function pull(args: ParsedArgs, agent: string): Promise<number> {
  const actions = flagString(args, "action");
  if (!actions || actions.trim().length === 0) {
    process.stderr.write(
      'grenz: usage: grenz break-glass <agent> --action <a,b> --reason "..." [--ttl <s>] [--quorum <n>]\n',
    );
    return 1;
  }
  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const params = new URLSearchParams({ agent, actions });
  const reason = flagString(args, "reason");
  if (reason) params.set("reason", reason);
  const ttl = flagString(args, "ttl");
  if (ttl) params.set("ttl", ttl);
  const quorum = flagString(args, "quorum");
  if (quorum) params.set("quorum", quorum);

  const res = await callAdmin(client, "POST", `/console/break-glass?${params.toString()}`);
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not break glass: ${err}\n`);
    return 1;
  }
  const body = res.body as { id: string; agent: string; actions: string[]; quorum: number; pulled_by: string; expires_at: number };
  const expires = new Date(body.expires_at).toISOString();
  process.stdout.write(
    [
      ``,
      `  🚨 Glass broken for ${body.agent} (by ${body.pulled_by})`,
      `  scope:   ${body.actions.join(", ")}`,
      `  quorum:  ${body.quorum} approver(s) — each request still needs a human tap`,
      `  expires: ${expires}`,
      ``,
      `  Denied actions in scope are now APPROVABLE for the window. This is loud`,
      `  and time-boxed; end it early with:  grenz revoke ${body.id}`,
      ``,
    ].join("\n") + "\n",
  );
  return 0;
}

async function list(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await callAdmin(client, "GET", "/console/break-glass");
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not list break-glass windows: ${err}\n`);
    return 1;
  }
  const rows = (res.body as { windows?: WindowRow[] }).windows ?? [];
  process.stdout.write(renderWindows(rows) + "\n");
  return 0;
}

export async function runBreakGlass(args: ParsedArgs): Promise<number> {
  const agent = args.positionals[0];
  return agent ? pull(args, agent) : list(args);
}
