/**
 * `grenz grant <agent> --actions <a,b> [--ttl <s>] [--reason "..."]`
 * `grenz grants`
 *
 * Temporarily widen an agent's OWN existing token for a bounded TTL — a
 * just-in-time exception to its static policy, not a new token like
 * delegation. Requires a running `grenz run` (live-system state, same as
 * delegations/approvals).
 *
 * To cut a grant short, use the kill-switch on its id:
 *   grenz revoke <grant-id>
 */
import { adminClient, callAdmin } from "./admin-client.ts";
import { flagString, type ParsedArgs } from "./args.ts";

interface GrantRow {
  readonly id: string;
  readonly agent: string;
  readonly actions: readonly string[];
  readonly reason: string;
  readonly expires_at: number;
  readonly revoked: boolean;
}

export async function runGrant(args: ParsedArgs): Promise<number> {
  const agent = args.positionals[0];
  if (!agent) {
    process.stderr.write('grenz: usage: grenz grant <agent> --actions <a,b> [--ttl <s>] [--reason "..."]\n');
    return 1;
  }
  const actions = flagString(args, "actions");
  if (!actions || actions.trim().length === 0) {
    process.stderr.write("grenz: --actions <a,b,...> is required\n");
    return 1;
  }

  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const params = new URLSearchParams({ agent, actions });
  const ttl = flagString(args, "ttl");
  if (ttl) params.set("ttl", ttl);
  const reason = flagString(args, "reason");
  if (reason) params.set("reason", reason);

  const res = await callAdmin(client, "POST", `/console/grants?${params.toString()}`);
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not grant: ${err}\n`);
    return 1;
  }

  const body = res.body as { grant_id: string; agent: string; actions: string[]; expires_at: number };
  const expires = new Date(body.expires_at).toISOString();
  process.stdout.write(
    [
      ``,
      `  Grant ${body.grant_id} for ${agent}`,
      `  scope:   ${body.actions.join(", ")}`,
      `  expires: ${expires}`,
      ``,
      `  ${agent}'s existing token can now do this immediately — no new token`,
      `  was minted. It reverts to static policy when the grant expires.`,
      `  Cut it early with:  grenz revoke ${body.grant_id}`,
      ``,
    ].join("\n") + "\n",
  );
  return 0;
}

export async function runGrants(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const res = await callAdmin(client, "GET", "/console/grants");
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not list grants: ${err}\n`);
    return 1;
  }

  const rows = (res.body as { grants?: GrantRow[] }).grants ?? [];
  if (rows.length === 0) {
    process.stdout.write("no active grants\n");
    return 0;
  }
  const lines = [`active grants (${rows.length}):`];
  for (const g of rows) {
    const expires = new Date(g.expires_at).toISOString();
    const state = g.revoked ? "REVOKED" : "live";
    const reason = g.reason ? `  "${g.reason}"` : "";
    lines.push(
      `  ${g.id}  ${g.agent.padEnd(14)} [${state.padEnd(7)}] ` +
        `${g.actions.join(",")}  expires ${expires}${reason}`,
    );
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
