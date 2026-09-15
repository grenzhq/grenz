/**
 * `grenz decoy token|upstream|list|remove` — plant and manage honeytokens.
 *
 * A decoy GRENZ_TOKEN (default `grenz_` prefix — byte-indistinguishable from a
 * real one) lives in the agents list; a decoy upstream lives in the upstreams
 * map with no credential. Any touch is high-confidence compromise: dispatch
 * revokes the toucher. These commands edit grenz.yaml (comments preserved) and
 * take effect on the next `grenz run` (config is not hot-reloaded). A trip IS a
 * revocation — `list` reads the plain revocation file, nothing new is stored.
 */
import { rename } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import { loadConfig, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { configSchema } from "../config/schema.ts";
import { generateToken, hashToken } from "../util/token.ts";
import {
  addDecoyAgent,
  addDecoyUpstream,
  removeDecoyAgent,
  removeDecoyUpstream,
} from "../config/rewrite.ts";
import { RevocationStore, RevocationError } from "../revoke/store.ts";
import { homeFlag, type ParsedArgs } from "./args.ts";

async function writeConfig(path: string, yaml: string): Promise<void> {
  const tmp = `${path}.tmp`;
  await Bun.write(tmp, yaml);
  await rename(tmp, path);
}

/** Re-validate before writing: never persist a config that won't load. Returns
 *  an error message, or null when the config is valid. */
function validate(yaml: string): string | null {
  try {
    const parsed = configSchema.safeParse(parseYaml(yaml));
    return parsed.success ? null : parsed.error.issues[0]?.message ?? "invalid config";
  } catch (err) {
    return err instanceof Error ? err.message : "invalid config";
  }
}

export async function runDecoy(args: ParsedArgs): Promise<number> {
  const sub = args.positionals[0];
  const home = homeFlag(args);
  const paths = grenzPaths(home);

  // Confirm the config exists/parses (also confirms `init` was run).
  try {
    await loadConfig(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const raw = await Bun.file(paths.config).text();

  if (sub === "token") {
    const name = args.positionals[1];
    if (!name) {
      process.stderr.write("grenz: usage: grenz decoy token <name>\n");
      return 1;
    }
    const token = generateToken(); // default grenz_ prefix — indistinguishable from a real token
    const hash = await hashToken(token);
    const result = addDecoyAgent(raw, name, hash);
    if (!result.ok) {
      process.stderr.write(`grenz: ${result.error}\n`);
      return 1;
    }
    const invalid = validate(result.yaml);
    if (invalid) {
      process.stderr.write(`grenz: refusing to write invalid config: ${invalid}\n`);
      return 1;
    }
    await writeConfig(paths.config, result.yaml);
    process.stdout.write(
      [
        ``,
        `  Planted decoy token "${name}". No legitimate workload should ever hold it —`,
        `  any request presenting it is high-confidence compromise and cuts the presenter off.`,
        ``,
        `  Decoy token (shown once — copy it now):`,
        ``,
        `      ${token}`,
        ``,
        `  Takes effect on the next \`grenz run\` (config is not hot-reloaded).`,
        ``,
      ].join("\n") + "\n",
    );
    return 0;
  }

  if (sub === "upstream") {
    const name = args.positionals[1];
    if (!name) {
      process.stderr.write("grenz: usage: grenz decoy upstream <name>\n");
      return 1;
    }
    const result = addDecoyUpstream(raw, name);
    if (!result.ok) {
      process.stderr.write(`grenz: ${result.error}\n`);
      return 1;
    }
    const invalid = validate(result.yaml);
    if (invalid) {
      process.stderr.write(`grenz: refusing to write invalid config: ${invalid}\n`);
      return 1;
    }
    await writeConfig(paths.config, result.yaml);
    process.stdout.write(
      `Planted decoy upstream "${name}". No policy should grant it; \`grenz policy lint\` flags any that does.\n` +
        `Takes effect on the next \`grenz run\`.\n`,
    );
    return 0;
  }

  if (sub === "remove") {
    const name = args.positionals[1];
    if (!name) {
      process.stderr.write("grenz: usage: grenz decoy remove <name>\n");
      return 1;
    }
    // Try agent first, then upstream. Both refuse non-decoys and unknown names.
    const asAgent = removeDecoyAgent(raw, name);
    const result = asAgent.ok ? asAgent : removeDecoyUpstream(raw, name);
    if (!result.ok) {
      // Neither matched a decoy (result is the upstream attempt's failure).
      // Prefer a "not a decoy" message (the name exists but is real) over a bare
      // "unknown …".
      const agentErr = asAgent.ok ? undefined : asAgent.error;
      const errs = [agentErr, result.error].filter((e): e is string => e !== undefined);
      const specific = errs.find((e) => !e.includes("unknown")) ?? errs[0];
      process.stderr.write(`grenz: ${specific ?? `no decoy named "${name}"`}\n`);
      return 1;
    }
    const invalid = validate(result.yaml);
    if (invalid) {
      process.stderr.write(`grenz: refusing to write invalid config: ${invalid}\n`);
      return 1;
    }
    await writeConfig(paths.config, result.yaml);
    process.stdout.write(`Removed decoy "${name}". Takes effect on the next \`grenz run\`.\n`);
    return 0;
  }

  if (sub === "list") {
    return runDecoyList(home, raw);
  }

  process.stderr.write("grenz: usage: grenz decoy <token|upstream|list|remove> ...\n");
  return 1;
}

/**
 * List planted decoys with armed/tripped state. A trip IS a revocation: the
 * running proxy persists every revoke to the same file, so reading it here is
 * current whether the proxy is up or down — no new persistence, no admin call.
 * Token trips join by the decoy agent id. Upstream trips revoke the toucher
 * (not the upstream), so those show `armed` with a pointer to `grenz
 * revocations`.
 */
function runDecoyList(home: string | undefined, raw: string): number {
  const parsed = configSchema.safeParse(parseYaml(raw));
  if (!parsed.success) {
    process.stderr.write(`grenz: ${parsed.error.issues[0]?.message ?? "invalid config"}\n`);
    return 1;
  }
  const cfg = parsed.data;
  const decoyAgents = cfg.agents.filter((a) => a.decoy);
  const decoyUpstreams = Object.entries(cfg.upstreams)
    .filter(([, u]) => u.decoy)
    .map(([n]) => n);

  const revokedReasons = new Map<string, string>();
  try {
    const store = new RevocationStore(grenzPaths(home).revocations);
    for (const r of store.list()) revokedReasons.set(r.agentId, r.reason);
  } catch (err) {
    if (!(err instanceof RevocationError)) throw err;
    // Corrupt revocation file: report armed state without trip overlay.
  }

  const lines: string[] = [];
  lines.push(`decoy tokens (${decoyAgents.length}):`);
  for (const a of decoyAgents) {
    const reason = revokedReasons.get(a.id);
    lines.push(`  ${a.id.padEnd(16)}  ${reason ? "TRIPPED" : "armed"}${reason ? `  (${reason})` : ""}`);
  }
  lines.push(`decoy upstreams (${decoyUpstreams.length}):`);
  for (const n of decoyUpstreams) {
    lines.push(`  ${n.padEnd(16)}  armed  (touches revoke the toucher — see \`grenz revocations\`)`);
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
