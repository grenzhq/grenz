/**
 * The falsifiable outcome statement `grenz protect` prints. Pure — takes the
 * finished plan and renders the story. It prints the GRENZ_TOKEN (which is meant
 * to be shown, like `init`) but NEVER the real upstream credential — that value
 * is not even an input here.
 *
 * Claim discipline: never "your agent can't do anything bad" — always "your
 * agent can't do anything irreversible without you." That survives reality.
 */

import type { SafeGrant } from "../policy/safe-defaults.ts";

export interface ProtectOutcome {
  readonly upstreamName: string;
  readonly envVar: string; // e.g. GITHUB_TOKEN — the var the token came from
  readonly listen: { readonly host: string; readonly port: number };
  readonly grant: SafeGrant;
  readonly grenzToken: string;
  readonly policyPath: string;
  readonly preference: "normal" | "strict";
}

export function renderProtectOutcome(o: ProtectOutcome): string {
  const gated = o.grant.require_approval.filter((a) => a !== "call:*");
  const L: string[] = [];

  L.push(`  Grenz is protecting ${o.upstreamName}.`);
  L.push(``);
  L.push(`  ✔ Your ${o.upstreamName} token is in the vault — your agent no longer holds it`);
  L.push(`      the real credential now lives only inside Grenz; ${o.envVar} can leave your agent's env`);
  L.push(``);
  if (gated.length > 0) {
    L.push(`  ✔ ${gated.length} irreversible action${gated.length === 1 ? "" : "s"} now require your approval:`);
    L.push(`      ${gated.join(", ")}`);
  }
  L.push(`  ✔ Everything else is allowed and logged — nothing here can DENY and break your agent mid-task.`);
  L.push(``);
  L.push(`  Point your agent at Grenz:`);
  L.push(`      base URL   http://${o.listen.host}:${o.listen.port}/u/${o.upstreamName}`);
  L.push(`      header     Authorization: Bearer ${o.grenzToken}`);
  L.push(``);
  L.push(`  Then:`);
  L.push(`      grenz run             start the firewall`);
  L.push(`      grenz status          watch every decision live`);
  L.push(`      grenz demo-attack     see what a scoped token can't do`);
  L.push(`      grenz demo-cascade    see one tripped decoy kill a whole agent swarm`);
  L.push(``);
  L.push(`  Your policy is at ${o.policyPath} (preference: ${o.preference}) — read it, edit it, commit it.`);

  return L.join("\n") + "\n";
}
