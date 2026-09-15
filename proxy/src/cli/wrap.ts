/**
 * `grenz wrap [--config <path>]` — the wrap ADVISOR (v1, read-only).
 *
 * Reads an MCP client config (default `./.mcp.json`), classifies its servers,
 * and prints the exact copy-paste steps to pull the wrappable ones behind Grenz.
 * It writes NO files, mints NO token, and never reproduces a secret value — the
 * emitted `grenz vault set` line pipes the secret from the user's own file.
 *
 * The in-place `--apply` transform is a future v2 that reuses this same
 * plan/render core.
 */
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";
import { loadConfig } from "../config/load.ts";
import { parseMcpConfig, planWrap, WrapError, type ListenAddr } from "../wrap/plan.ts";
import { renderAdvisor } from "../wrap/render.ts";

const DEFAULT_LISTEN: ListenAddr = { host: "127.0.0.1", port: 8787 };

/** Best-effort listener address for the loopback urls the advisor emits. Falls
 *  back to the default when there is no Grenz home yet — the advisor is useful
 *  before `grenz run`, and a unix-socket listener has no http host:port. */
async function resolveListen(home: string | undefined): Promise<ListenAddr> {
  try {
    const config = await loadConfig(home);
    const l = config.listen as { host?: unknown; port?: unknown };
    if (typeof l.host === "string" && typeof l.port === "number") {
      return { host: l.host, port: l.port };
    }
  } catch {
    // no home / unreadable config — defaults are fine for a read-only advisor.
  }
  return DEFAULT_LISTEN;
}

export async function runWrap(args: ParsedArgs): Promise<number> {
  const configPath = flagString(args, "config") ?? ".mcp.json";
  const file = Bun.file(configPath);
  if (!(await file.exists())) {
    process.stderr.write(
      `grenz: no MCP config at "${configPath}". Pass --config <path> (e.g. ~/.claude.json).\n`,
    );
    return 1;
  }

  let text: string;
  try {
    text = await file.text();
  } catch {
    process.stderr.write(`grenz: could not read "${configPath}".\n`);
    return 1;
  }

  let parsed;
  try {
    parsed = parseMcpConfig(text);
  } catch (err) {
    // WrapError messages are deliberately generic — they never echo the source.
    const message = err instanceof WrapError ? err.message : "could not parse the MCP config";
    process.stderr.write(`grenz: ${message}\n`);
    return 1;
  }

  const listen = await resolveListen(homeFlag(args));
  const plan = planWrap(parsed, listen);
  process.stdout.write(renderAdvisor(plan, { listen, configPath }) + "\n");
  return 0;
}
