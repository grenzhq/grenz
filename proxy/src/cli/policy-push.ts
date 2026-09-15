/**
 * `grenz policy push` — upload a pre-signed policy bundle (the exact artifact
 * `grenz policy sign` emits) to the cloud plane, authenticated by a PUBLISH
 * token (distinct from the proxy's pull token used by `policy_source`). This
 * command POSTs the bundle bytes verbatim — it never re-signs, re-serializes,
 * or normalizes them. The plane only validates bundle shape and stores/serves
 * bytes as-is (invariant 3: the plane distributes, it never decides).
 */
import { z } from "zod";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { VaultError } from "../vault/store.ts";
import { grenzPaths } from "../config/paths.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

const PUSH_USAGE =
  "grenz: usage: grenz policy push --bundle <file>|- --url <url> " +
  "(--token <tok> | --token-key <vault-key> | $GRENZ_PUBLISH_TOKEN)\n";

const pushResponseSchema = z.object({ version: z.number() });

type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: string };

/**
 * Resolve the bundle text to push. `-` reads stdin to completion; anything
 * else is read as a file path. Returned VERBATIM — no trim/normalize — since
 * the bytes must match exactly what `policy sign` produced (and what the
 * plane will verify/serve unmodified).
 */
async function resolveBundleText(bundlePath: string): Promise<Result<string>> {
  if (bundlePath === "-") {
    return { ok: true, value: await Bun.stdin.text() };
  }
  const file = Bun.file(bundlePath);
  if (!(await file.exists())) {
    return { ok: false, error: `bundle not found at ${bundlePath}` };
  }
  return { ok: true, value: await file.text() };
}

/**
 * Resolve the publish token from exactly one of three sources: `--token`,
 * `GRENZ_PUBLISH_TOKEN`, or `--token-key` (an age vault lookup, the same
 * `localVault.get(key)` call `run.ts` uses for `policy_source.org_token_key`).
 * Two-or-more or zero sources is a deny-by-default error — silently picking
 * one would be surprising, and silently accepting none would push
 * unauthenticated.
 */
async function resolveToken(args: ParsedArgs): Promise<Result<string>> {
  const flagToken = flagString(args, "token");
  const envToken = process.env.GRENZ_PUBLISH_TOKEN;
  const hasEnvToken = envToken !== undefined && envToken.length > 0;
  const tokenKey = flagString(args, "token-key");

  const sourceCount = (flagToken !== undefined ? 1 : 0) + (hasEnvToken ? 1 : 0) + (tokenKey !== undefined ? 1 : 0);
  if (sourceCount === 0) {
    return {
      ok: false,
      error: "no publish token given — pass --token <tok>, set GRENZ_PUBLISH_TOKEN, or --token-key <vault-key>",
    };
  }
  if (sourceCount > 1) {
    return {
      ok: false,
      error: "multiple token sources given — pass exactly one of --token, GRENZ_PUBLISH_TOKEN, --token-key",
    };
  }

  if (flagToken !== undefined) return { ok: true, value: flagToken };
  if (hasEnvToken) return { ok: true, value: envToken };

  // tokenKey is set (sourceCount === 1 and the other two are absent).
  const paths = grenzPaths(homeFlag(args));
  const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  try {
    const token = await vault.get(tokenKey!);
    if (token === undefined) {
      return { ok: false, error: `no credential found for vault key "${tokenKey}"` };
    }
    return { ok: true, value: token };
  } catch (err) {
    if (err instanceof VaultError) return { ok: false, error: `vault: ${err.message}` };
    throw err;
  }
}

export async function runPolicyPush(args: ParsedArgs): Promise<number> {
  const bundlePath = flagString(args, "bundle");
  const url = flagString(args, "url");
  if (!bundlePath || !url) {
    process.stderr.write(PUSH_USAGE);
    return 1;
  }

  const bundleResult = await resolveBundleText(bundlePath);
  if (!bundleResult.ok) {
    process.stderr.write(`grenz: ${bundleResult.error}\n`);
    return 1;
  }

  const tokenResult = await resolveToken(args);
  if (!tokenResult.ok) {
    process.stderr.write(`grenz: ${tokenResult.error}\n`);
    return 1;
  }

  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${tokenResult.value}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ bundle: bundleResult.value }),
    });
  } catch {
    // Same wording as the pull-side fetchRemotePolicy() network-error path
    // (src/policy/source.ts) -- never echo the underlying error, which could
    // embed the URL or, on some fetch implementations, request internals.
    process.stderr.write("grenz: policy source unreachable\n");
    return 1;
  }

  if (!res.ok) {
    const text = await res.text();
    process.stderr.write(`grenz: ${text}\n`);
    return 1;
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    process.stderr.write("grenz: malformed response from policy source (expected {version})\n");
    return 1;
  }
  const parsed = pushResponseSchema.safeParse(body);
  if (!parsed.success) {
    process.stderr.write("grenz: malformed response from policy source (expected {version})\n");
    return 1;
  }

  process.stdout.write(`pushed v${parsed.data.version}\n`);
  return 0;
}
