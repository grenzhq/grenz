/**
 * `grenz token create|list|revoke` — manage named admin tokens (console RBAC
 * operators) over the admin API. An admin credential is required. Operational
 * access control / separation of duties, NOT an audit surface.
 */
import { adminClient, callAdmin } from "./admin-client.ts";
import { flagString, type ParsedArgs } from "./args.ts";

interface TokenRow {
  readonly name: string;
  readonly role: string;
  readonly createdAt: number;
  readonly revokedAt: number | null;
}

/** Pure formatter for `grenz token list`. */
export function renderTokenList(rows: readonly TokenRow[]): string {
  if (rows.length === 0) return "no named admin tokens (the bootstrap admin token is always active)";
  return rows
    .map((r) => `  ${r.name.padEnd(20)} ${r.role.padEnd(9)} ${r.revokedAt !== null ? "revoked" : "active"}`)
    .join("\n");
}

async function create(args: ParsedArgs): Promise<number> {
  const name = args.positionals[1];
  const role = flagString(args, "role") ?? "viewer";
  if (!name) {
    process.stderr.write("grenz: usage: grenz token create <name> --role viewer|approver|admin\n");
    return 1;
  }
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await callAdmin(client, "POST", "/console/tokens", { body: { name, role } });
  if (!res) return 1;
  if (res.status !== 200) {
    process.stderr.write(`grenz: ${(res.body as { error?: string }).error ?? "failed"}\n`);
    return 1;
  }
  const b = res.body as { name: string; role: string; token: string };
  process.stdout.write(
    `created admin token "${b.name}" (${b.role})\n\n  ${b.token}\n\n` +
      `Store it now — it will not be shown again.\n`,
  );
  return 0;
}

async function list(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await callAdmin(client, "GET", "/console/tokens");
  if (!res) return 1;
  process.stdout.write(renderTokenList((res.body as { tokens?: TokenRow[] }).tokens ?? []) + "\n");
  return 0;
}

async function revoke(args: ParsedArgs): Promise<number> {
  const name = args.positionals[1];
  if (!name) {
    process.stderr.write("grenz: usage: grenz token revoke <name>\n");
    return 1;
  }
  const client = await adminClient(args);
  if (typeof client === "number") return client;
  const res = await callAdmin(client, "DELETE", `/console/tokens/${encodeURIComponent(name)}`);
  if (!res) return 1;
  if (res.status !== 200) {
    process.stderr.write(`grenz: ${(res.body as { error?: string }).error ?? "failed"}\n`);
    return 1;
  }
  process.stdout.write(`revoked admin token "${name}"\n`);
  return 0;
}

export async function runToken(args: ParsedArgs): Promise<number> {
  const sub = args.positionals[0];
  if (sub === "create") return create(args);
  if (sub === "list") return list(args);
  if (sub === "revoke") return revoke(args);
  process.stderr.write("grenz: usage: grenz token create <name> --role <role> | list | revoke <name>\n");
  return 1;
}
