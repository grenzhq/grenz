/**
 * `grenz doctor` — offline preflight checks against a Grenz home. Gathers
 * config/policy/vault/port state, runs the pure checks in doctor/checks.ts,
 * renders a ✓/⚠/✗ report, and exits 1 on any hard failure so
 * `grenz doctor && grenz run` gates startup. Makes NO network calls.
 */
import { existsSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { connect } from "node:net";
import { loadConfig, loadPolicy, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { resolveSocketPath } from "../config/socket-path.ts";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { VaultError } from "../vault/store.ts";
import { buildReport, worstStatus, type DoctorInputs, type Check, type PlaneBlock } from "../doctor/checks.ts";
import { RELAY_TOKEN_KEY } from "../config/schema.ts";
import { homeFlag, type ParsedArgs } from "./args.ts";

const SLACK_WEBHOOK_KEY = "slack_webhook";
const LLM_API_KEY = "llm_api_key";
const DEFAULT_PORT = 8787;

/** True if a value is present and non-empty (a present-but-empty secret is "missing"). */
function nonEmpty(v: string | undefined): boolean {
  return v !== undefined && v.length > 0;
}

/** Local bind probe — no traffic, no egress. True when the port cannot be bound. */
function isPortInUse(host: string, port: number): boolean {
  try {
    const s = Bun.serve({ hostname: host, port, fetch: () => new Response("x") });
    s.stop(true);
    return false;
  } catch {
    return true;
  }
}

const SYMBOL: Record<Check["status"], string> = { ok: "✓", warn: "⚠", fail: "✗" };

/** Permission bits of a path, or null when it does not exist. */
function statMode(path: string): number | null {
  try {
    return statSync(path).mode & 0o777;
  } catch {
    return null;
  }
}

/**
 * True when a socket file exists but nothing is listening — a proxy that exited
 * uncleanly. A local connect attempt only; no egress, in keeping with doctor's
 * existing local bind probe.
 */
function isStaleSocket(path: string): Promise<boolean> {
  if (!existsSync(path)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const c = connect(path);
    const done = (stale: boolean): void => {
      c.destroy();
      resolve(stale);
    };
    c.on("connect", () => done(false)); // a live proxy owns it
    c.on("error", () => done(true));
  });
}

export async function runDoctor(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);

  // --- config ---
  let configError: string | null = null;
  // Named while reading the config; resolved against the vault further down.
  const planeKeyNames: { block: PlaneBlock; key: string }[] = [];
  const planeKeys: { block: PlaneBlock; key: string; present: boolean }[] = [];
  let upstreams: DoctorInputs["upstreams"] = {};
  let agents: DoctorInputs["agents"] = [];
  let socket: DoctorInputs["socket"] = null;
  let port = DEFAULT_PORT;
  let host = "127.0.0.1";
  let telemetryEnabled = false;
  try {
    const config = await loadConfig(home);
    upstreams = Object.fromEntries(
      Object.entries(config.upstreams).map(([n, u]) =>
        u.decoy
          ? [n, { type: u.type, decoy: true as const, credential: null }]
          : [n, { type: u.type, decoy: false as const, credential: u.credential }],
      ),
    );
    agents = config.agents.map((a) => ({ id: a.id, expiresAtMs: a.expiresAtMs }));
    if (config.listen.socket !== undefined) {
      const resolved = resolveSocketPath(config.listen.socket, paths.home);
      socket = resolved.ok
        ? {
            path: resolved.path,
            pathError: null,
            dirMode: statMode(dirname(resolved.path)),
            stale: await isStaleSocket(resolved.path),
          }
        : { path: config.listen.socket, pathError: resolved.error, dirMode: null, stale: false };
    }
    port = config.listen.port;
    host = config.listen.host;
    telemetryEnabled = config.telemetry?.enabled ?? false;
    // Blocks that need a vault key before they can do anything. Telemetry only
    // counts when it is actually switched on — a disabled block needs nothing.
    if (config.policy_source) {
      planeKeyNames.push({ block: "policy_source", key: config.policy_source.org_token_key });
    }
    if (config.telemetry?.enabled) {
      planeKeyNames.push({ block: "telemetry", key: config.telemetry.org_token_key });
    }
    if (config.relay) planeKeyNames.push({ block: "relay", key: RELAY_TOKEN_KEY });
  } catch (err) {
    if (err instanceof ConfigError) configError = err.message;
    else throw err;
  }

  // --- policy ---
  let policyError: string | null = null;
  let grantCount = 0;
  let grantTools: string[] = [];
  try {
    const policy = await loadPolicy(home);
    grantCount = policy.grants.size;
    grantTools = [...policy.grants.keys()];
  } catch (err) {
    if (err instanceof ConfigError) policyError = err.message;
    else throw err;
  }

  // --- vault + credentials + integrations ---
  const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  let vaultError: string | null = null;
  const credentialPresent: Record<string, boolean> = {};
  const integrations = { slackWebhook: false, llmApiKey: false, telemetryEnabled };
  try {
    await vault.keys(); // forces decrypt; a bad identity/corrupt vault throws here
    const wanted = new Set<string>(
      Object.values(upstreams)
        .filter((u) => !u.decoy)
        .map((u) => u.credential as string),
    );
    for (const key of wanted) credentialPresent[key] = nonEmpty(await vault.get(key));
    integrations.slackWebhook = nonEmpty(await vault.get(SLACK_WEBHOOK_KEY));
    integrations.llmApiKey = nonEmpty(await vault.get(LLM_API_KEY));
    for (const k of planeKeyNames) {
      planeKeys.push({ block: k.block, key: k.key, present: nonEmpty(await vault.get(k.key)) });
    }
  } catch (err) {
    if (err instanceof VaultError) vaultError = err.message;
    else throw err;
  }

  const inputs: DoctorInputs = {
    configError,
    upstreams,
    policyError,
    grantCount,
    grantTools,
    vaultError,
    credentialPresent,
    adminTokenPresent: await Bun.file(paths.adminToken).exists(),
    agents,
    now: Date.now(),
    socket,
    port,
    portInUse: isPortInUse(host, port),
    integrations,
    planeKeys,
  };

  const checks = buildReport(inputs);
  const lines = [``, `  Grenz doctor — ${paths.home}`, ``];
  for (const c of checks) {
    lines.push(`  ${SYMBOL[c.status]} ${c.name.padEnd(13)} ${c.detail}`);
  }
  const worst = worstStatus(checks);
  const fails = checks.filter((c) => c.status === "fail").length;
  const warns = checks.filter((c) => c.status === "warn").length;
  lines.push(``);
  lines.push(
    worst === "ok"
      ? `  all clear`
      : `  ${fails} problem(s), ${warns} warning(s)` +
          (worst === "fail" ? " — fix the ✗ lines before grenz run" : ""),
  );
  lines.push(``);
  process.stdout.write(lines.join("\n") + "\n");

  return worst === "fail" ? 1 : 0;
}
