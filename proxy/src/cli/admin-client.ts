/**
 * Thin client for the proxy's loopback admin API.
 *
 * The pending-approval and revocation state lives in the RUNNING proxy (it
 * holds the blocked requests and the live kill-list), so CLI commands operate
 * it over HTTP using the local admin token. Loopback only; the admin token
 * never grants upstream access.
 */
import { loadConfig, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { readAdminToken } from "../admin/token.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

export interface AdminClient {
  readonly base: string;
  readonly token: string;
}

/** Resolve the admin base URL + token, or an exit code if no token exists. */
export async function adminClient(args: ParsedArgs): Promise<AdminClient | number> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);
  const token = await readAdminToken(paths.adminToken);
  if (!token) {
    process.stderr.write("grenz: no admin token found — run `grenz init` (or `grenz run`) first\n");
    return 1;
  }
  let host = "127.0.0.1";
  let port = 8787;
  try {
    const config = await loadConfig(home);
    host = config.listen.host === "0.0.0.0" ? "127.0.0.1" : config.listen.host;
    port = config.listen.port;
  } catch (err) {
    if (!(err instanceof ConfigError)) throw err;
    // fall back to defaults
  }
  const portOverride = flagString(args, "port");
  if (portOverride !== undefined && Number.isInteger(Number(portOverride))) {
    port = Number(portOverride);
  }
  return { base: `http://${host}:${port}`, token };
}

export interface AdminResponse {
  readonly status: number;
  readonly body: unknown;
}

/**
 * Call the admin API. Returns null when the proxy is unreachable (the caller
 * decides how to handle that — approvals report it; the kill-switch falls back
 * to writing its file directly). Set `quiet` to suppress the unreachable
 * message when the caller has its own fallback path.
 */
export async function callAdmin(
  client: AdminClient,
  method: string,
  path: string,
  opts?: { quiet?: boolean; body?: unknown },
): Promise<AdminResponse | null> {
  try {
    const headers: Record<string, string> = { "x-grenz-admin": client.token };
    if (opts?.body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${client.base}${path}`, {
      method,
      headers,
      body: opts?.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  } catch {
    if (!opts?.quiet) {
      process.stderr.write(
        `grenz: could not reach the proxy at ${client.base} — is \`grenz run\` running?\n`,
      );
    }
    return null;
  }
}
