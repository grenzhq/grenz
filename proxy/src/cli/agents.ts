/**
 * `grenz agents` — list first-class agents the running proxy is serving.
 *
 * Shows each agent's id, its policy profile (or `-` for the shared default), its
 * action/target scope, and expiry — a live view from the admin API, so a
 * console-minted agent appears without a restart. No token material is ever
 * shown (the endpoint returns none); this is operational visibility, not an
 * audit trail.
 */
import { adminClient, callAdmin } from "./admin-client.ts";
import type { ParsedArgs } from "./args.ts";

interface AgentRow {
  readonly id: string;
  readonly policy: string | null;
  readonly actions: readonly string[];
  readonly targets: readonly string[];
  readonly decoy: boolean;
  readonly expires_at: string | null;
}

/** Join a scope list for the column, or `-` when unrestricted. */
function scope(list: readonly string[]): string {
  return list.length > 0 ? list.join(",") : "-";
}

export async function runAgents(args: ParsedArgs): Promise<number> {
  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const res = await callAdmin(client, "GET", "/console/agents");
  if (!res) return 1;
  if (res.status !== 200) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not list agents: ${err}\n`);
    return 1;
  }

  const rows = (res.body as { agents?: AgentRow[] }).agents ?? [];
  if (rows.length === 0) {
    process.stdout.write("no agents\n");
    return 0;
  }

  // Width the id/profile columns to their contents (bounded); the rest flow.
  const idW = Math.max(2, ...rows.map((r) => r.id.length));
  const profW = Math.max(7, ...rows.map((r) => (r.policy ?? "-").length));
  const header = `${"ID".padEnd(idW)}  ${"PROFILE".padEnd(profW)}  ACTIONS  TARGETS  EXPIRES`;
  const lines = [header];
  for (const r of rows) {
    const profile = r.decoy ? "(decoy)" : (r.policy ?? "-");
    const expires = r.expires_at ?? "never";
    lines.push(
      `${r.id.padEnd(idW)}  ${profile.padEnd(profW)}  ${scope(r.actions)}  ${scope(r.targets)}  ${expires}`,
    );
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
