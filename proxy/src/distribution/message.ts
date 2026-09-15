/**
 * The exact bytes an Ed25519 signature covers for a policy bundle, in ONE place
 * imported by the signer (keypair.ts) and verifier (verify.ts) so they cannot
 * drift. Also the bundle's operational digest. Signs a control INPUT (the policy
 * artifact + its profiles). NOT tamper-evident logging.
 */
import type { ProfileEntry } from "../policy/profile-entry.ts";

export function canonicalProfiles(profiles: readonly ProfileEntry[]): string {
  const sorted = [...profiles].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return JSON.stringify(sorted.map((p) => [p.name, p.policy]));
}

/**
 * profiles === null (no `profiles` field) → legacy v1 layout.
 * profiles is an array (INCLUDING []) → v2 layout, binding the field's PRESENCE
 * into the signature (so an empty "clear" array cannot be stripped down to
 * "no field" without breaking the signature). Presence, not length, selects.
 */
export function bundleSignatureMessage(
  version: number,
  policy: string,
  profiles: readonly ProfileEntry[] | null,
): Uint8Array {
  const body =
    profiles === null
      ? `grenz-policy-signature-v1\n${version}\n${policy}`
      : `grenz-policy-signature-v2\n${version}\n${policy}\n${canonicalProfiles(profiles)}`;
  return new TextEncoder().encode(body);
}

/** sha256 (first 12 hex) over the default YAML AND the canonical profiles — an
 *  operational fingerprint (not the signature) that changes when EITHER changes,
 *  so a same-version content change is detectable (refresh memory-clear).
 *
 *  Domain-separated + length-prefixed so no two distinct (policy, profiles) pairs
 *  collide: a `v1`/`v2` tag distinguishes absent(null) from present profiles, and
 *  the policy length is emitted before the policy so a boundary character (a raw
 *  `\x00` or a newline inside the policy) cannot slide bytes across the
 *  policy/profiles seam. (A plain `\x00` join was NOT a real separator — a v1
 *  policy ending in `\x00`+canonical-JSON aliased a v2 split.) */
export async function bundleDigest(
  policyYaml: string,
  profiles: readonly ProfileEntry[] | null,
): Promise<string> {
  const tag = profiles === null ? "v1" : "v2";
  const canon = profiles === null ? "" : canonicalProfiles(profiles);
  const input = `grenz-bundle-digest-${tag}\n${policyYaml.length}\n${policyYaml}\n${canon}`;
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Buffer.from(new Uint8Array(d)).toString("hex").slice(0, 12);
}
