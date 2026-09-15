/**
 * `grenz revoke <agent> | restore <agent> | revocations`
 *
 * The kill-switch. `revoke` cuts an agent off immediately: the running proxy
 * denies its every request from that moment on — mid-flight, no restart. These
 * are thin clients of the proxy's loopback admin API, but unlike approvals the
 * kill-switch must work even when the proxy is DOWN: if it is unreachable the
 * command writes the revocation file directly and it applies on the next
 * `grenz run`.
 */
import { grenzPaths } from "../config/paths.ts";
import { RevocationStore, RevocationError, type RevocationRecord } from "../revoke/store.ts";
import { FleetRevocationStore } from "../revocation/store.ts";
import { adminClient, callAdmin } from "./admin-client.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

/** Open the on-disk store, mapping a corrupt file to a clean CLI error. */
function openStore(home: string | undefined): RevocationStore | number {
  const paths = grenzPaths(home);
  try {
    return new RevocationStore(paths.revocations);
  } catch (err) {
    if (err instanceof RevocationError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
}

export async function runRevoke(args: ParsedArgs): Promise<number> {
  const agentId = args.positionals[0];
  if (!agentId) {
    process.stderr.write('grenz: usage: grenz revoke <agent> [--reason "..."]\n');
    return 1;
  }
  const reason = flagString(args, "reason") ?? "manual";
  const home = homeFlag(args);

  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const path = `/console/revocations/${encodeURIComponent(agentId)}?reason=${encodeURIComponent(reason)}`;
  const res = await callAdmin(client, "POST", path, { quiet: true });
  if (res) {
    if (res.status === 200) {
      process.stdout.write(`revoked ${agentId} (live) — reason: ${reason}\n`);
      return 0;
    }
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not revoke ${agentId}: ${err}\n`);
    return 1;
  }

  // Proxy not running: persist directly so it applies on the next start.
  const store = openStore(home);
  if (typeof store === "number") return store;
  store.revoke(agentId, reason, Date.now());
  process.stdout.write(
    `revoked ${agentId} (saved — proxy not running; applies on next \`grenz run\`)\n`,
  );
  return 0;
}

export async function runRestore(args: ParsedArgs): Promise<number> {
  const agentId = args.positionals[0];
  if (!agentId) {
    process.stderr.write("grenz: usage: grenz restore <agent>\n");
    return 1;
  }
  const home = homeFlag(args);

  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const res = await callAdmin(client, "DELETE", `/console/revocations/${encodeURIComponent(agentId)}`, {
    quiet: true,
  });
  if (res) {
    if (res.status === 200) {
      const body = res.body as { removed?: boolean; fleet_revoked?: boolean; fleet_version?: number };
      if (body.fleet_revoked === true) {
        // Honest refusal: the local revocation was lifted, but the signed fleet
        // set still cuts this agent off. Only a new signed set can restore it.
        process.stdout.write(
          `${agentId} is revoked fleet-wide by signed set v${body.fleet_version ?? 0} — ` +
            `publish a new set to restore (local revocation ${body.removed ? "lifted" : "was absent"})\n`,
        );
        return 0;
      }
      process.stdout.write(body.removed === true ? `restored ${agentId} (live)\n` : `${agentId} was not revoked\n`);
      return 0;
    }
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not restore ${agentId}: ${err}\n`);
    return 1;
  }

  const store = openStore(home);
  if (typeof store === "number") return store;
  const removed = store.restore(agentId);
  try {
    const fleet = new FleetRevocationStore(grenzPaths(home).fleetRevocations);
    if (fleet.has(agentId)) {
      process.stdout.write(
        `${agentId} is revoked fleet-wide by signed set v${fleet.version()} — publish a new set to restore ` +
          `(local revocation ${removed ? "lifted" : "was absent"})\n`,
      );
      return 0;
    }
  } catch {
    /* absent or corrupt fleet cache — fall through to the plain local message */
  }
  process.stdout.write(
    removed
      ? `restored ${agentId} (saved; applies on next \`grenz run\`)\n`
      : `${agentId} was not revoked\n`,
  );
  return 0;
}

/** Append a summary of the cached signed fleet set, if any. Offline-capable —
 *  reads the file directly. Stays quiet on absent/corrupt cache (the run banner
 *  surfaces corruption at startup). */
function printFleetSection(home: string | undefined): void {
  let fleet: FleetRevocationStore;
  try {
    fleet = new FleetRevocationStore(grenzPaths(home).fleetRevocations);
  } catch {
    return;
  }
  if (fleet.version() === 0 && fleet.count() === 0) return;
  const agents = fleet.list();
  const expiry = fleet.expiresAt();
  const lines = [
    ``,
    `fleet set v${fleet.version()} (${agents.length} cut off fleet-wide${
      expiry ? `, expires ${new Date(expiry * 1000).toISOString()}` : ""
    }):`,
    ...agents.map((a) => `  ${a}`),
  ];
  process.stdout.write(lines.join("\n") + "\n");
}

function printRecords(records: readonly RevocationRecord[]): void {
  if (records.length === 0) {
    process.stdout.write("no revoked agents\n");
    return;
  }
  const lines = [`revoked agents (${records.length}):`];
  for (const r of records) {
    const when = new Date(r.ts).toISOString();
    lines.push(`  ${r.agentId.padEnd(14)}  ${when}  ${r.reason}`);
  }
  process.stdout.write(lines.join("\n") + "\n");
}

export async function runRevocations(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);

  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const res = await callAdmin(client, "GET", "/console/revocations", { quiet: true });
  if (res) {
    if (res.status === 200) {
      printRecords((res.body as { revocations?: RevocationRecord[] }).revocations ?? []);
      printFleetSection(home);
      return 0;
    }
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not list revocations: ${err}\n`);
    return 1;
  }

  // Proxy not running: read the file directly.
  const store = openStore(home);
  if (typeof store === "number") return store;
  printRecords(store.list());
  printFleetSection(home);
  return 0;
}
