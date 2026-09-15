/**
 * `grenz connect <policy-url>` — point this proxy at a control plane in one
 * command.
 *
 * Before this, connecting meant opening grenz.yaml, pasting an
 * indentation-sensitive block into the right place, and separately piping a
 * token into `grenz vault set`. Two of those three steps are things a person
 * does once and gets wrong silently; the YAML paste in particular fails in ways
 * that surface much later as "the plane's policy never applies".
 *
 * What it does, in order: store the token, then write the config. That order
 * matters — a config naming a vault key that isn't there is exactly the broken
 * state `grenz doctor` exists to report, so if the vault write fails, nothing
 * has been promised in the config yet.
 *
 * The token is never taken from argv: it is read from stdin, or prompted for
 * without echo. `grenz vault set` set that rule and this follows it, for the
 * same reason — argv lands in shell history and the process table.
 */
import { rename } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import { grenzPaths } from "../config/paths.ts";
import { configSchema, LOCAL_PLANE_HOSTS } from "../config/schema.ts";
import { setPolicySource, setTelemetry, type RewriteResult } from "../config/rewrite.ts";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { VaultError } from "../vault/store.ts";
import { flagBool, flagString, homeFlag, type ParsedArgs } from "./args.ts";
import { readSecret } from "./read-secret.ts";
import { pollUntilReady, startDeviceFlow } from "./device-flow.ts";

/** The vault key both blocks read. Matches the schema defaults. */
const ORG_TOKEN_KEY = "cloud_org_token";
/** Pull every 5 minutes; refuse to serve a policy older than an hour. */
const REFRESH_SECONDS = 300;
const MAX_AGE_SECONDS = 3600;
/** Where `grenz connect` with no arguments looks for a plane. `--plane` overrides. */
const DEFAULT_PLANE = "https://relay.grenz.dev";

/** Telemetry reports hourly. Only ever written with --telemetry. */
const TELEMETRY_INTERVAL_SECONDS = 3600;

/**
 * A plane URL this command is willing to write.
 *
 * Plain http is refused off-localhost. The proxy sends the org token to this
 * URL and runs whatever policy comes back, so over http anyone on the path both
 * learns the token and chooses the policy. The fetcher does not enforce this
 * today; refusing to *author* such a config is the cheap half of the fix.
 */
export function checkPlaneUrl(raw: string): { ok: true; url: URL } | { ok: false; error: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: `not a URL: ${raw}` };
  }
  const local = LOCAL_PLANE_HOSTS.has(url.hostname);
  if (url.protocol === "http:" && !local) {
    return {
      ok: false,
      error: `refusing to connect over plain http (${url.host}) — the org token and the policy both travel this URL. Use https.`,
    };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { ok: false, error: `unsupported scheme "${url.protocol}" — use https` };
  }
  return { ok: true, url };
}

/**
 * The stats endpoint that belongs to a policy URL: `/api/policy/<agent>` on the
 * same origin becomes `/api/stats`. Derived rather than asked for, so the
 * console can print one URL instead of two — but only when the path really has
 * that shape. A guess on an unrecognized path would silently point telemetry at
 * something that isn't the plane, so that case asks for --stats-url instead.
 */
export function deriveStatsUrl(policyUrl: URL): string | undefined {
  const marker = "/api/policy/";
  const at = policyUrl.pathname.lastIndexOf(marker);
  if (at < 0) return undefined;
  const prefix = policyUrl.pathname.slice(0, at);
  return new URL(`${prefix}/api/stats`, policyUrl.origin).toString();
}

/**
 * A name the plane supplied, made safe to print.
 *
 * Everything else from the plane lands in a file or the vault; this lands in a
 * terminal, where control characters are instructions. A hostile or merely
 * sloppy plane should not be able to repaint the line that tells you which
 * agent you just connected as.
 */
export function safeForTerminal(raw: string): string {
  // eslint-disable-next-line no-control-regex
  return raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 80);
}

async function writeConfig(path: string, yaml: string): Promise<void> {
  const tmp = `${path}.tmp`;
  await Bun.write(tmp, yaml);
  await rename(tmp, path);
}

/** Never persist a config that will not load. */
function validate(yaml: string): string | null {
  try {
    const parsed = configSchema.safeParse(parseYaml(yaml));
    return parsed.success ? null : parsed.error.issues[0]?.message ?? "invalid config";
  } catch (err) {
    return err instanceof Error ? err.message : "invalid config";
  }
}

export async function runConnect(args: ParsedArgs): Promise<number> {
  const raw = args.positionals[0];
  // No URL: ask the plane to authorize this machine instead of asking the
  // operator to carry a token here by hand.
  if (raw === undefined) return runDeviceConnect(args);

  const checked = checkPlaneUrl(raw);
  if (!checked.ok) {
    process.stderr.write(`grenz: ${checked.error}\n`);
    return 1;
  }

  const home = homeFlag(args);
  const paths = grenzPaths(home);
  const force = flagBool(args, "force");
  // Comma-separated so one flag covers key rotation (pin new, re-sign, drop old).
  const publicKeys = (flagString(args, "public-key") ?? "")
    .split(",")
    .map((k) => k.trim())
    .filter((k) => k.length > 0);
  const wantTelemetry = flagBool(args, "telemetry");

  let configText: string;
  try {
    configText = await Bun.file(paths.config).text();
  } catch {
    process.stderr.write(`grenz: no grenz.yaml at ${paths.config} — run \`grenz init\` first\n`);
    return 1;
  }

  // Resolve the telemetry endpoint before touching anything, so an
  // underivable one fails before the vault is written.
  let statsUrl: string | undefined;
  if (wantTelemetry) {
    statsUrl = flagString(args, "stats-url") ?? deriveStatsUrl(checked.url);
    if (statsUrl === undefined) {
      process.stderr.write(`grenz: cannot derive the stats endpoint from ${raw} — pass --stats-url <url>\n`);
      return 1;
    }
    const checkedStats = checkPlaneUrl(statsUrl);
    if (!checkedStats.ok) {
      process.stderr.write(`grenz: --stats-url: ${checkedStats.error}\n`);
      return 1;
    }
  }

  // 1. Work out the new config. Pure — so a refusal here (an existing
  //    policy_source, a file that won't parse) costs nothing and leaves the
  //    vault untouched.
  let result: RewriteResult = setPolicySource(
    configText,
    {
      url: checked.url.toString(),
      orgTokenKey: ORG_TOKEN_KEY,
      refreshSeconds: REFRESH_SECONDS,
      maxAgeSeconds: MAX_AGE_SECONDS,
      publicKeys,
    },
    force,
  );
  if (result.ok && wantTelemetry && statsUrl !== undefined) {
    result = setTelemetry(
      result.yaml,
      { endpoint: statsUrl, orgTokenKey: ORG_TOKEN_KEY, intervalSeconds: TELEMETRY_INTERVAL_SECONDS },
      force,
    );
  }
  if (!result.ok) {
    process.stderr.write(`grenz: ${result.error}\n`);
    return 1;
  }

  // 2. The token, only once the config is known to be writable. Stored
  //    BEFORE the file is written, so grenz.yaml never names a vault key
  //    that isn't there — the exact state `grenz doctor` exists to report. Already present = don't ask again; re-pointing a proxy at a
  //    new agent on the same plane reuses the same org token.
  const store = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  let haveToken = false;
  try {
    haveToken = (await store.get(ORG_TOKEN_KEY)) !== undefined;
  } catch (err) {
    const why = err instanceof VaultError ? `${err.code}: ${err.message}` : String(err);
    process.stderr.write(`grenz: vault error (${why})\n`);
    return 1;
  }

  if (!haveToken) {
    const token = await readSecret("Paste the pull token (input hidden): ");
    if (token.length === 0) {
      process.stderr.write(
        `grenz: no token given — nothing was changed.\n` +
          `       Mint one in the console, then:  grenz connect ${raw}\n`,
      );
      return 1;
    }
    try {
      await store.set(ORG_TOKEN_KEY, token);
    } catch (err) {
      const why = err instanceof VaultError ? `${err.code}: ${err.message}` : String(err);
      process.stderr.write(`grenz: could not store the token (${why}) — nothing was changed.\n`);
      return 1;
    }
    // Bytes, never the value.
    process.stdout.write(`stored "${ORG_TOKEN_KEY}" (${token.length} bytes)\n`);
  } else {
    process.stdout.write(`vault key "${ORG_TOKEN_KEY}" already present — kept\n`);
  }

  const invalid = validate(result.yaml);
  if (invalid !== null) {
    process.stderr.write(`grenz: refusing to write an invalid config — ${invalid}\n`);
    return 1;
  }
  await writeConfig(paths.config, result.yaml);

  process.stdout.write(
    `\n  connected to ${checked.url.host}\n` +
      `  policy   pulls every ${REFRESH_SECONDS}s, refuses to serve one older than ${MAX_AGE_SECONDS}s\n` +
      (publicKeys.length > 0
        ? `  bundle   signature required — ${publicKeys.length} key(s) pinned\n`
        : `  bundle   unsigned — anyone who can serve this URL chooses the policy\n`) +
      (wantTelemetry
        ? `  stats    aggregate counts every ${TELEMETRY_INTERVAL_SECONDS}s to ${statsUrl}\n`
        : `  stats    off — add --telemetry to report aggregate counts\n`) +
      `\n  Next:  grenz doctor   then   grenz run\n`,
  );
  return 0;
}

/**
 * `grenz connect` with no arguments: device authorization.
 *
 * Prints a short code, waits while a human approves it in the console, and
 * receives a pull token minted for the agent they picked. Nothing is written
 * until that token is in hand, so an abandoned or refused approval leaves this
 * machine exactly as it was.
 */
export async function runDeviceConnect(args: ParsedArgs): Promise<number> {
  const plane = (flagString(args, "plane") ?? DEFAULT_PLANE).replace(/\/+$/, "");
  const checkedPlane = checkPlaneUrl(plane);
  if (!checkedPlane.ok) {
    process.stderr.write(`grenz: --plane: ${checkedPlane.error}\n`);
    return 1;
  }

  const paths = grenzPaths(homeFlag(args));
  const force = flagBool(args, "force");
  const wantTelemetry = flagBool(args, "telemetry");

  // Read once now purely to fail fast: there is no point printing a code and
  // waiting fifteen minutes for someone to approve a machine that has no home.
  try {
    await Bun.file(paths.config).text();
  } catch {
    process.stderr.write(`grenz: no grenz.yaml at ${paths.config} — run \`grenz init\` first\n`);
    return 1;
  }

  const started = await startDeviceFlow(plane, { fetch: globalThis.fetch });
  if (!started.ok) {
    process.stderr.write(`grenz: ${started.error}\n`);
    return 1;
  }
  const { start } = started;

  process.stdout.write(
    `\n  Open   ${start.verificationUri}\n` +
      `  Code   ${start.userCode}\n\n` +
      `  Waiting for approval… (expires in ${Math.round(start.expiresInSeconds / 60)} min, Ctrl-C to stop)\n`,
  );

  const result = await pollUntilReady(plane, start, {
    fetch: globalThis.fetch,
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
  });
  if (!result.ok) {
    process.stderr.write(`\ngrenz: ${result.error}\n`);
    return 1;
  }
  const { ready } = result;

  // The plane names the URL this proxy will pull policy from forever after, so
  // it gets the same check a hand-written one does. The manual path refuses a
  // plaintext policy source; the device path must not be the way around it.
  const checkedPolicy = checkPlaneUrl(ready.policyUrl);
  if (!checkedPolicy.ok) {
    process.stderr.write(`grenz: the plane returned a policy URL this proxy will not use — ${checkedPolicy.error}\n`);
    return 1;
  }
  if (ready.statsUrl) {
    const checkedStats = checkPlaneUrl(ready.statsUrl);
    if (!checkedStats.ok) {
      process.stderr.write(`grenz: the plane returned a stats URL this proxy will not use — ${checkedStats.error}\n`);
      return 1;
    }
  }

  // Re-read: approval can be minutes away, and whatever the file says NOW is
  // what the edit has to be based on. Writing a rewrite of a stale copy would
  // silently drop anything changed while this command waited.
  let configText: string;
  try {
    configText = await Bun.file(paths.config).text();
  } catch {
    process.stderr.write(`grenz: grenz.yaml disappeared while waiting for approval — nothing was changed.\n`);
    return 1;
  }

  const statsUrl = ready.statsUrl || deriveStatsUrl(checkedPolicy.url);
  if (wantTelemetry && statsUrl === undefined) {
    process.stderr.write(`grenz: the plane did not say where to report stats — pass --stats-url <url>\n`);
    return 1;
  }

  // Config first: pure, so a refusal here (an existing policy_source) costs
  // nothing. The token is stored only once the file is known to be writable.
  let rewritten: RewriteResult = setPolicySource(
    configText,
    {
      url: ready.policyUrl,
      orgTokenKey: ORG_TOKEN_KEY,
      refreshSeconds: REFRESH_SECONDS,
      maxAgeSeconds: MAX_AGE_SECONDS,
    },
    force,
  );
  if (rewritten.ok && wantTelemetry && statsUrl !== undefined) {
    rewritten = setTelemetry(
      rewritten.yaml,
      { endpoint: statsUrl, orgTokenKey: ORG_TOKEN_KEY, intervalSeconds: TELEMETRY_INTERVAL_SECONDS },
      force,
    );
  }
  if (!rewritten.ok) {
    process.stderr.write(`grenz: ${rewritten.error}\n`);
    return 1;
  }
  const invalid = validate(rewritten.yaml);
  if (invalid !== null) {
    process.stderr.write(`grenz: refusing to write an invalid config — ${invalid}\n`);
    return 1;
  }

  const store = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  try {
    await store.set(ORG_TOKEN_KEY, ready.token);
  } catch (err) {
    const why = err instanceof VaultError ? `${err.code}: ${err.message}` : String(err);
    process.stderr.write(`grenz: could not store the token (${why}) — nothing was changed.\n`);
    return 1;
  }
  await writeConfig(paths.config, rewritten.yaml);

  process.stdout.write(
    `\n  ✓ connected as ${safeForTerminal(ready.agent)}\n` +
      `  policy   pulls every ${REFRESH_SECONDS}s from ${checkedPolicy.url.host}\n` +
      (wantTelemetry ? `  stats    every ${TELEMETRY_INTERVAL_SECONDS}s\n` : `  stats    off\n`) +
      `\n  Next:  grenz run\n`,
  );
  return 0;
}
