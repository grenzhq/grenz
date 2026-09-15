/**
 * `grenz revocations sign` — sign the current revocation SET into a versioned
 * bundle the plane can serve to a fleet. Runs on the operator's workstation or
 * CI; the private key never touches a proxy or the plane.
 *
 * Ids come from stdin (comma/whitespace/newline separated) by default, or from
 * this box's LOCAL revocations with --from-local. An EMPTY set is a legitimate,
 * publishable state ("nobody is revoked") and needs no workaround. This signs a
 * control INPUT (the current set), not a record of what happened — no reason,
 * actor, or timestamp is signed.
 */
import { grenzPaths } from "../config/paths.ts";
import { RevocationStore, RevocationError } from "../revoke/store.ts";
import { signRevocationSet } from "../distribution/keypair.ts";
import { MAX_POLICY_VERSION } from "../distribution/verify.ts";
import { flagBool, flagString, homeFlag, type ParsedArgs } from "./args.ts";

export function parseAgentList(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s.length > 0))].sort();
}

export async function signRevocationText(
  agents: string[],
  keyPath: string,
  version: number,
  expiresIn: number | null,
  nowSeconds: number,
): Promise<string> {
  const privateKeyB64 = (await Bun.file(keyPath).text()).trim();
  const expiresAt = expiresIn === null ? null : nowSeconds + expiresIn;
  return signRevocationSet(agents, version, expiresAt, privateKeyB64);
}

export async function runRevocationsSign(args: ParsedArgs): Promise<number> {
  const keyPath = flagString(args, "key");
  const versionRaw = flagString(args, "version");
  if (!keyPath || !versionRaw) {
    process.stderr.write(
      "grenz: usage: grenz revocations sign --key <privkey-file> --version <N> [--from-local] [--expires-in <seconds>]\n" +
        "        (agent ids on stdin, comma/space/newline separated; empty = nobody revoked)\n",
    );
    return 1;
  }
  const version = Number(versionRaw);
  if (!Number.isSafeInteger(version) || version < 1 || version > MAX_POLICY_VERSION) {
    process.stderr.write(`grenz: --version must be an integer between 1 and ${MAX_POLICY_VERSION}\n`);
    return 1;
  }

  const expiresInRaw = flagString(args, "expires-in");
  let expiresIn: number | null = null;
  if (expiresInRaw !== undefined) {
    expiresIn = Number(expiresInRaw);
    if (!Number.isSafeInteger(expiresIn) || expiresIn < 60 || expiresIn > 604800) {
      process.stderr.write("grenz: --expires-in must be an integer between 60 and 604800 (seconds)\n");
      return 1;
    }
  }

  let agents: string[];
  if (flagBool(args, "from-local")) {
    try {
      const store = new RevocationStore(grenzPaths(homeFlag(args)).revocations);
      agents = [...new Set(store.list().map((r) => r.agentId))].sort();
    } catch (err) {
      if (err instanceof RevocationError) {
        process.stderr.write(`grenz: ${err.message}\n`);
        return 1;
      }
      throw err;
    }
    // Restore is by OMISSION: a published set is authoritative and complete, so
    // any fleet-revoked id NOT in THIS box's local list is un-revoked fleet-wide.
    // --from-local publishes only what this one box sees — warn loudly so an
    // operator does not silently lift someone else's revocation.
    process.stderr.write(
      `grenz: WARNING --from-local publishes ONLY this box's ${agents.length} local revocation(s):\n` +
        `        ${agents.length > 0 ? agents.join(", ") : "(none)"}\n` +
        `        Any agent revoked fleet-wide but NOT in this list will be UN-REVOKED everywhere.\n` +
        `        Prefer piping the full intended set on stdin unless you are sure this box is authoritative.\n`,
    );
  } else {
    agents = parseAgentList(await Bun.stdin.text());
  }

  try {
    const nowSeconds = Math.floor(Date.now() / 1000);
    process.stdout.write((await signRevocationText(agents, keyPath, version, expiresIn, nowSeconds)) + "\n");
  } catch (err) {
    process.stderr.write(`grenz: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
  return 0;
}
