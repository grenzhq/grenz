/**
 * `grenz wrap` advisor rendering — turns a WrapPlan into copy-paste steps.
 *
 * It reads ONLY plan metadata (names, urls, header names, schemes, vault keys) —
 * never a secret value (the plan holds none). The vault-set step is a command
 * the user runs that pipes the secret from THEIR file into the vault, so the
 * secret never passes through Grenz's output.
 */
import type { WrapPlan, ListenAddr } from "./plan.ts";

export interface RenderOpts {
  readonly listen: ListenAddr;
  readonly configPath: string;
}

const RULE = "────────────────────────────────────────";

/** The shell one-liner that moves a header's value from the config into the
 *  vault without it passing through Grenz. Strips the scheme prefix when set. */
function vaultCommand(configPath: string, server: string, header: string, sch: string, vaultKey: string): string {
  const path = `.mcpServers[${JSON.stringify(server)}].headers[${JSON.stringify(header)}]`;
  const extract = sch ? `${path} | sub("^${sch} ";"")` : path;
  return `jq -r '${extract}' ${JSON.stringify(configPath)} | grenz vault set ${vaultKey}`;
}

function loopbackUrl(listen: ListenAddr, upstream: string): string {
  return `http://${listen.host}:${listen.port}/u/${upstream}`;
}

export function renderAdvisor(plan: WrapPlan, opts: RenderOpts): string {
  const wrap = plan.servers.filter((s) => s.action === "wrap");
  const skip = plan.servers.filter((s) => s.action === "skip");
  const out: string[] = [];

  out.push(`grenz wrap — ${opts.configPath}`);
  out.push("");
  if (wrap.length === 0) {
    out.push("No servers to wrap.");
    if (skip.length > 0) out.push("");
  } else {
    out.push(`${wrap.length} server(s) can go behind Grenz. Apply the steps below, then restart \`grenz run\`.`);
    out.push("");
  }

  for (const s of wrap) {
    if (s.action !== "wrap") continue;
    const headerValue = s.scheme ? `${s.scheme} <YOUR_GRENZ_TOKEN>` : "<YOUR_GRENZ_TOKEN>";
    out.push(`${RULE}`);
    out.push(`  ${s.name}  →  ${loopbackUrl(opts.listen, s.upstream)}`);
    out.push(`${RULE}`);
    out.push("");
    out.push("  1) Move the credential into the vault (the secret flows from your file — never shown here):");
    out.push(`       ${vaultCommand(opts.configPath, s.name, s.header, s.scheme, s.vaultKey)}`);
    out.push("     (no jq? run `grenz vault set " + s.vaultKey + "` and paste the value.)");
    out.push("");
    out.push("  2) Add this upstream to grenz.yaml under `upstreams:`");
    out.push(`       ${s.upstream}:`);
    out.push("         type: mcp");
    out.push(`         base_url: ${s.url}`);
    out.push(`         credential: ${s.vaultKey}`);
    out.push("         inject:");
    out.push(`           header: ${s.header}`);
    out.push(`           scheme: ${JSON.stringify(s.scheme)}`);
    out.push("");
    out.push(`  3) Replace mcpServers[${JSON.stringify(s.name)}] in the config with:`);
    out.push(`       ${JSON.stringify(s.name)}: {`);
    out.push(`         "type": "http",`);
    out.push(`         "url": ${JSON.stringify(loopbackUrl(opts.listen, s.upstream))},`);
    out.push(`         "headers": { ${JSON.stringify(s.header)}: ${JSON.stringify(headerValue)} }`);
    out.push("       }");
    out.push("     (use the GRENZ_TOKEN printed by `grenz init` / `grenz rotate <agent>`.)");
    out.push("");
    out.push("  4) Open what this server may do in policy.yaml (deny-by-default — nothing is allowed until you say so):");
    out.push("       grants:");
    out.push(`         - tool: ${s.upstream}`);
    out.push("           allow:");
    out.push('             - "*:read"      # start read-only; widen deliberately');
    out.push("");
  }

  if (skip.length > 0) {
    out.push("Skipped:");
    for (const s of skip) {
      if (s.action !== "skip") continue;
      out.push(`  • ${s.name} — ${s.reason}`);
    }
    out.push("");
  }

  if (wrap.length > 0) {
    out.push("After applying: restart `grenz run` (config is not hot-reloaded), then your MCP client talks to Grenz.");
  }

  return out.join("\n");
}
