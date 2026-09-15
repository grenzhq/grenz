/**
 * `grenz delegate <agent> --actions <a,b> [--targets <glob,glob>] [--ttl <s>] [--note "..."]`
 * `grenz delegations`
 *
 * Mint an attenuated child token for a sub-agent, or list the live ones. The
 * operator mints on behalf of a configured agent via the loopback admin API
 * (the agentic path is the token-authenticated POST /delegate on the proxy).
 * Delegation is live-system state, so these require a running `grenz run`.
 *
 * To revoke a delegation early, use the kill-switch on its id:
 *   grenz revoke <delegation-id>
 * Revoking the PARENT agent cascades to every delegation it spawned.
 */
import { adminClient, callAdmin } from "./admin-client.ts";
import { flagString, type ParsedArgs } from "./args.ts";

interface DelegationRow {
  readonly id: string;
  readonly parent: string;
  readonly actions: readonly string[];
  readonly targets?: readonly string[];
  readonly note: string;
  readonly expires_at: number;
  /** Billable allowed actions this sub-token spent in the last hour. */
  readonly spent: number;
  readonly revoked: boolean;
}

export async function runDelegate(args: ParsedArgs): Promise<number> {
  const agent = args.positionals[0];
  if (!agent) {
    process.stderr.write(
      'grenz: usage: grenz delegate <agent> --actions <a,b> [--targets <glob,glob>] [--ttl <s>] [--note "..."]\n',
    );
    return 1;
  }
  const actions = flagString(args, "actions");
  if (!actions || actions.trim().length === 0) {
    process.stderr.write("grenz: --actions <a,b,...> is required (a subset of the agent's scope)\n");
    return 1;
  }

  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const params = new URLSearchParams({ agent, actions });
  const targets = flagString(args, "targets");
  if (targets && targets.trim().length > 0) params.set("targets", targets);
  const ttl = flagString(args, "ttl");
  if (ttl) params.set("ttl", ttl);
  const note = flagString(args, "note");
  if (note) params.set("note", note);

  const res = await callAdmin(client, "POST", `/console/delegations?${params.toString()}`);
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not delegate: ${err}\n`);
    return 1;
  }

  const body = res.body as {
    token: string;
    delegation_id: string;
    actions: string[];
    targets?: string[];
    expires_at: number;
  };
  const expires = new Date(body.expires_at).toISOString();
  const targetLine =
    body.targets && body.targets.length > 0
      ? [`  targets: ${body.targets.join(", ")}`]
      : [];
  process.stdout.write(
    [
      ``,
      `  Delegation ${body.delegation_id} for ${agent}`,
      `  scope:   ${body.actions.join(", ")}`,
      ...targetLine,
      `  expires: ${expires}`,
      ``,
      `  Child token (shown once — hand it to the sub-agent):`,
      ``,
      `      ${body.token}`,
      ``,
      `  It can do at most the intersection of the above scope and ${agent}'s`,
      `  live policy, and dies when it expires or when ${agent} is revoked.`,
      `  Cut it early with:  grenz revoke ${body.delegation_id}`,
      ``,
    ].join("\n") + "\n",
  );
  return 0;
}

export async function runDelegations(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const res = await callAdmin(client, "GET", "/console/delegations");
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not list delegations: ${err}\n`);
    return 1;
  }

  const rows = (res.body as { delegations?: DelegationRow[] }).delegations ?? [];
  if (rows.length === 0) {
    process.stdout.write("no active delegations\n");
    return 0;
  }
  const lines = [`active delegations (${rows.length}):`];
  for (const d of rows) {
    const expires = new Date(d.expires_at).toISOString();
    const state = d.revoked ? "REVOKED" : "live";
    const note = d.note ? `  "${d.note}"` : "";
    const scope =
      d.targets && d.targets.length > 0
        ? `${d.actions.join(",")} @ ${d.targets.join(",")}`
        : d.actions.join(",");
    lines.push(
      `  ${d.id}  ${d.parent.padEnd(14)} [${state.padEnd(7)}] ` +
        `${scope}  spent ${d.spent}/h  expires ${expires}${note}`,
    );
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
