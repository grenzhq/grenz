/**
 * `grenz rotate <agent>` — mint a fresh GRENZ_TOKEN for an agent and rewrite
 * its token_hash in grenz.yaml (comments preserved). The new token is printed
 * once and takes effect on the next `grenz run` (config is not hot-reloaded).
 * For an immediate cutoff of a leaked token, `grenz revoke` first.
 */
import { rename } from "node:fs/promises";
import { loadConfig, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { generateToken, hashToken } from "../util/token.ts";
import { setAgentTokenHash } from "../config/rewrite.ts";
import { homeFlag, type ParsedArgs } from "./args.ts";

export async function runRotate(args: ParsedArgs): Promise<number> {
  const agentId = args.positionals[0];
  if (!agentId) {
    process.stderr.write("grenz: usage: grenz rotate <agent>\n");
    return 1;
  }

  const home = homeFlag(args);
  const paths = grenzPaths(home);

  // Validate the config exists and parses (fail closed; also confirms `init`).
  let config;
  try {
    config = await loadConfig(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // A born-dead rotation: if the target agent's expires_at is already past, the
  // freshly minted token is rejected the moment it is used. Warn, but NEVER clear
  // expires_at — silently extending identity lifetime is a fail-open the operator
  // did not ask for. Rotation proceeds; the operator edits or removes the field.
  const targetExpiresAtMs = config.agents.find((a) => a.id === agentId)?.expiresAtMs ?? null;
  const bornExpired = targetExpiresAtMs !== null && targetExpiresAtMs <= Date.now();

  const raw = await Bun.file(paths.config).text();
  const token = generateToken();
  const newHash = await hashToken(token);

  const result = setAgentTokenHash(raw, agentId, newHash);
  if (!result.ok) {
    process.stderr.write(`grenz: ${result.error}\n`);
    return 1;
  }

  // Atomic write: temp + rename, so a crash never leaves a half-written config.
  const tmp = `${paths.config}.tmp`;
  await Bun.write(tmp, result.yaml);
  await rename(tmp, paths.config);

  process.stdout.write(
    [
      ``,
      `  Rotated GRENZ_TOKEN for "${agentId}".`,
      ``,
      `  New token (shown once — copy it now):`,
      ``,
      `      ${token}`,
      ``,
      `  The new token takes effect on the next \`grenz run\`; the old token is`,
      `  rejected then. For an immediate cutoff of a leaked token, run`,
      `  \`grenz revoke ${agentId}\` now (in-memory, no restart), then \`grenz restore`,
      `  ${agentId}\` once the new token is in use.`,
      ``,
    ].join("\n") + "\n",
  );
  if (bornExpired) {
    const iso = new Date(targetExpiresAtMs).toISOString();
    process.stderr.write(
      `grenz: warning: "${agentId}" expires_at (${iso}) is already in the past — the new token is ` +
        `rejected the moment it is used. expires_at was left in place; edit or remove it in grenz.yaml.\n`,
    );
  }
  return 0;
}
