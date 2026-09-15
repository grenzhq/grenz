/**
 * `grenz vault set <key>` / `grenz vault list`.
 *
 * `set` reads the secret from a prompt or stdin — never argv, so it does not land in
 * shell history or the process table. `list` prints key NAMES only — never a
 * value.
 */
import { grenzPaths } from "../config/paths.ts";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { VaultError } from "../vault/store.ts";
import { loadConfig } from "../config/load.ts";
import { homeFlag, type ParsedArgs } from "./args.ts";
import { readSecret } from "./read-secret.ts";

/** Best-effort: warn that a remote backend reads UPSTREAM creds, so this local
 *  write only affects meta-credentials (slack_webhook, the Vault token, …). */
async function remoteBackendNote(args: ParsedArgs): Promise<void> {
  try {
    const config = await loadConfig(homeFlag(args));
    if (config.credential_store.type === "hashicorp-vault") {
      process.stderr.write(
        `note: upstream credentials are read from HashiCorp Vault; this wrote the ` +
          `LOCAL store (meta-credentials + the Vault token only).\n`,
      );
    }
  } catch {
    /* no config yet, or unreadable — nothing to note */
  }
}

function storeFor(args: ParsedArgs): AgeFileCredentialStore {
  const paths = grenzPaths(homeFlag(args));
  return new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
}

async function vaultSet(args: ParsedArgs, key: string): Promise<number> {
  // On a terminal this prompts; piped, it reads stdin. It used to only do the
  // latter, so running it by hand blocked with no output and looked hung.
  const value = await readSecret(`Paste the value for "${key}" (input hidden): `);
  if (value.length === 0) {
    process.stderr.write(
      `grenz: no value given. Paste it at the prompt, or pipe it:  printf %s "$SECRET" | grenz vault set ${key}\n`,
    );
    return 1;
  }
  const store = storeFor(args);
  try {
    await store.set(key, value);
  } catch (err) {
    if (err instanceof VaultError) {
      process.stderr.write(`grenz: vault error (${err.code}): ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  // Report bytes, never the value.
  process.stdout.write(`stored "${key}" (${value.length} bytes)\n`);
  await remoteBackendNote(args);
  return 0;
}

async function vaultList(args: ParsedArgs): Promise<number> {
  const store = storeFor(args);
  let keys: string[];
  try {
    keys = await store.keys();
  } catch (err) {
    if (err instanceof VaultError) {
      process.stderr.write(`grenz: vault error (${err.code}): ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  if (keys.length === 0) {
    process.stdout.write("(vault is empty)\n");
    return 0;
  }
  process.stdout.write(keys.join("\n") + "\n");
  return 0;
}

export async function runVault(args: ParsedArgs): Promise<number> {
  const sub = args.positionals[0];
  switch (sub) {
    case "set": {
      const key = args.positionals[1];
      if (!key) {
        process.stderr.write("grenz: usage: grenz vault set <key>   (value read from stdin)\n");
        return 1;
      }
      return vaultSet(args, key);
    }
    case "list":
      return vaultList(args);
    default:
      process.stderr.write("grenz: usage: grenz vault <set|list>\n");
      return 1;
  }
}
