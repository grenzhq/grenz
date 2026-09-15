/**
 * `grenz policy keygen` / `grenz policy sign`. Runs on the operator's
 * workstation or CI — produces the org signing keypair and signs a compiled
 * policy into a distributable bundle. The PRIVATE key never goes on a proxy or
 * the plane; only the printed PUBLIC key is pinned into proxy config, so a
 * compromised plane can serve only what the org already signed.
 */
import { chmodSync, writeFileSync } from "node:fs";
import { generateSigningKeypair, signBundle } from "../distribution/keypair.ts";
import { MAX_POLICY_VERSION } from "../distribution/verify.ts";
import { compilePolicyYaml } from "../policy/compile.ts";
import { PROFILE_NAME_RE, type ProfileEntry } from "../policy/profile-entry.ts";
import { loadConfig, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { flagBool, flagString, homeFlag, type ParsedArgs } from "./args.ts";

export async function keygenText(): Promise<string> {
  const kp = await generateSigningKeypair();
  return [
    "# Grenz policy signing keypair (Ed25519)",
    "#",
    "# PRIVATE KEY - keep secret; store it in CI secrets or on an admin workstation.",
    "# NEVER put it on a proxy or the control plane.",
    `private key: ${kp.privateKeyB64}`,
    "",
    "# PUBLIC KEY - paste into each proxy's grenz.yaml under policy_source.public_key.",
    "# Deliver it out-of-band (not through the plane).",
    `public key:  ${kp.publicKeyB64}`,
    "",
  ].join("\n");
}

export async function signText(
  policyPath: string,
  keyPath: string,
  version: number,
  profiles: readonly ProfileEntry[] | null,
): Promise<string> {
  const policyYaml = await Bun.file(policyPath).text();
  // Never sign a policy that would not compile - a signed-but-broken bundle is a
  // valid artifact that every proxy in the fleet would reject at load time.
  const compiled = compilePolicyYaml(policyYaml);
  if (!compiled.ok) throw new Error(`refusing to sign - policy does not compile: ${compiled.error}`);
  const privateKeyB64 = (await Bun.file(keyPath).text()).trim();
  return signBundle(policyYaml, version, privateKeyB64, profiles);
}

/**
 * Pure version-bump guard for `policy sign`. `force` always wins; a null
 * `lastSigned` means nothing has been signed from this home yet (first sign
 * always passes); otherwise the requested version must be STRICTLY greater —
 * re-signing the same version (or an older one) would let a stale bundle
 * silently replace a newer one already in the fleet's hands.
 */
export function nextVersionOk(requested: number, lastSigned: number | null, force: boolean): boolean {
  return force || lastSigned === null || requested > lastSigned;
}

/**
 * `--out <path>` writes the BARE base64 private key (0600) — the exact format
 * `sign --key` reads. Redirecting the human-readable keygen output into a file
 * would include the comment block and fail to parse, so this is the safe path.
 */
export async function keygenToFile(path: string): Promise<string> {
  const kp = await generateSigningKeypair();
  writeFileSync(path, kp.privateKeyB64, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best-effort perms */
  }
  return [
    `# Private key written to ${path} (mode 0600). Keep it secret; it never goes`,
    "# on a proxy or the control plane.",
    "",
    "# PUBLIC KEY - paste into each proxy's grenz.yaml under policy_source.public_key.",
    `public key:  ${kp.publicKeyB64}`,
    "",
  ].join("\n");
}

export async function runPolicyKeygen(args: ParsedArgs): Promise<number> {
  const out = flagString(args, "out");
  process.stdout.write(out ? await keygenToFile(out) : await keygenText());
  return 0;
}

const SIGN_USAGE =
  "grenz: usage: grenz policy sign <policy.yaml> --key <privkey-file> --version <N> " +
  "[--profile name=path[,name=path...]] [--clear-profiles] [--force-version]\n";

/**
 * Parse `--profile name=path[,name=path...]` into bundle `ProfileEntry`
 * values. The argv parser (args.ts) keeps only the LAST value for a repeated
 * flag, so `--profile a=pa --profile b=pb` would silently drop `a` — a comma
 * list is the only way to pass more than one profile in a single invocation.
 * Returns an error string (never throws) so the caller can print a clean
 * `grenz: ...` message instead of a stack trace.
 */
async function parseProfileFlag(raw: string): Promise<{ ok: true; profiles: ProfileEntry[] } | { ok: false; error: string }> {
  const profiles: ProfileEntry[] = [];
  const seen = new Set<string>();
  for (const entry of raw.split(",")) {
    const eq = entry.indexOf("=");
    if (eq <= 0) return { ok: false, error: `invalid --profile entry "${entry}" — expected name=path` };
    const name = entry.slice(0, eq);
    const filePath = entry.slice(eq + 1);
    if (!PROFILE_NAME_RE.test(name)) {
      return { ok: false, error: `invalid profile name "${name}" — must match ${PROFILE_NAME_RE}` };
    }
    if (seen.has(name)) return { ok: false, error: `duplicate profile "${name}" in --profile` };
    seen.add(name);
    const file = Bun.file(filePath);
    if (!(await file.exists())) return { ok: false, error: `profile "${name}" file not found at ${filePath}` };
    profiles.push({ name, policy: await file.text() });
  }
  return { ok: true, profiles };
}

export async function runPolicySign(args: ParsedArgs): Promise<number> {
  // `policy` is stripped before runPolicy, so positionals[0] === "sign".
  const policyPath = args.positionals[1];
  const keyPath = flagString(args, "key");
  const versionRaw = flagString(args, "version");
  if (!policyPath || !keyPath || !versionRaw) {
    process.stderr.write(SIGN_USAGE);
    return 1;
  }
  const version = Number(versionRaw);
  if (!Number.isSafeInteger(version) || version < 1 || version > MAX_POLICY_VERSION) {
    // Bounded so the signer can never mint a bundle whose version would become a
    // proxy's permanent anti-rollback floor (a stray epoch-nanos or CI run id).
    process.stderr.write(`grenz: --version must be an integer between 1 and ${MAX_POLICY_VERSION}\n`);
    return 1;
  }

  // Decide the `profiles` argument. error-on-omission: a bare `sign` with no
  // --profile/--clear-profiles can never SILENTLY drop a profile set the home
  // has declared — it must fail loudly and name the flags that fix it.
  const clearProfiles = flagBool(args, "clear-profiles");
  const profileRaw = flagString(args, "profile");
  let profiles: readonly ProfileEntry[] | null;
  if (clearProfiles) {
    profiles = [];
  } else if (profileRaw !== undefined) {
    const parsed = await parseProfileFlag(profileRaw);
    if (!parsed.ok) {
      process.stderr.write(`grenz: ${parsed.error}\n`);
      return 1;
    }
    profiles = parsed.profiles;
  } else {
    const home = homeFlag(args);
    // `grenz policy sign` is designed to run off-proxy/CI with only policy.yaml +
    // the private key, so an ABSENT grenz.yaml is not a misconfig — it just means
    // "no profiles declared" ⇒ emit a v1 bundle (profiles = null). Only consult
    // config when the file EXISTS: a config that exists but is schema-invalid
    // still fails closed (loadConfig throws), and one that declares a non-empty
    // policy_profiles still triggers the loud error-on-omission below.
    const configPath = grenzPaths(home).config;
    if (!(await Bun.file(configPath).exists())) {
      profiles = null;
    } else {
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
      if (Object.keys(config.policy_profiles).length > 0) {
        process.stderr.write(
          "grenz: this home declares policy_profiles — pass --profile name=path for each, or --clear-profiles\n",
        );
        return 1;
      }
      profiles = null;
    }
  }

  // Version-bump guard: strictly-greater-than the last version this home
  // signed, unless --force-version. Prevents an accidental re-sign of a stale
  // version from quietly shadowing a newer bundle already in the fleet's hands.
  const paths = grenzPaths(homeFlag(args));
  const versionFile = Bun.file(paths.lastSignedVersion);
  let lastSigned: number | null = null;
  if (await versionFile.exists()) {
    const raw = (await versionFile.text()).trim();
    const parsedVersion = Number(raw);
    if (!Number.isSafeInteger(parsedVersion)) {
      process.stderr.write(`grenz: corrupt ${paths.lastSignedVersion} — expected an integer\n`);
      return 1;
    }
    lastSigned = parsedVersion;
  }
  const forceVersion = flagBool(args, "force-version");
  if (!nextVersionOk(version, lastSigned, forceVersion)) {
    process.stderr.write(
      `grenz: --version ${version} must be greater than the last signed version (${lastSigned}) — ` +
        "pass --force-version to override\n",
    );
    return 1;
  }

  try {
    const bundle = await signText(policyPath, keyPath, version, profiles);
    process.stdout.write(bundle + "\n");
    await Bun.write(paths.lastSignedVersion, String(version));
  } catch (err) {
    process.stderr.write(`grenz: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
  return 0;
}
