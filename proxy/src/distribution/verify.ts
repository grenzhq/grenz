/**
 * Pure verification of a signed policy bundle. Async only for WebCrypto; does NO
 * network. Runs at LOAD time (startup + background refresh), never on the request
 * path. Verifies a control INPUT (the policy artifact) — this is supply-chain
 * integrity, NOT tamper-evident logging. Every failure is a fixed code carrying
 * no key bytes or policy content.
 */
import { z } from "zod";
import type { BundleDenyCode, BundleVerifyResult } from "./types.ts";
import { profileEntrySchema, type ProfileEntry } from "../policy/profile-entry.ts";
import { bundleSignatureMessage, bundleDigest } from "./message.ts";

/**
 * Versions are bounded on both ends. A version <= 0 is nonsense (the floor
 * starts at 0), and an absurd one — a fat-fingered epoch-nanos or CI run id —
 * would become the persisted floor and block every future policy on that proxy
 * forever. MAX_POLICY_VERSION is far above any real release count.
 */
export const MAX_POLICY_VERSION = 1_000_000_000_000;

const bundleSchema = z
  .object({
    version: z.number().int().min(1).max(MAX_POLICY_VERSION),
    policy: z.string(),
    profiles: z.array(profileEntrySchema).max(256).optional(),
    signature: z.string(),
  })
  .strict();

function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export async function policyDigest(policyYaml: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(policyYaml));
  return Buffer.from(new Uint8Array(d)).toString("hex").slice(0, 12);
}

export async function verifyPolicyBundle(
  bundleText: string,
  pinnedKeys: string[],
  minVersion: number,
): Promise<BundleVerifyResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bundleText);
  } catch {
    return { ok: false, code: "bundle_malformed" };
  }
  const env = bundleSchema.safeParse(parsed);
  if (!env.success) return { ok: false, code: "bundle_malformed" };
  const { version, policy, signature, profiles } = env.data;
  const profilesForSig: readonly ProfileEntry[] | null = profiles === undefined ? null : profiles;
  if (profilesForSig !== null) {
    const seen = new Set<string>();
    for (const p of profilesForSig) {
      if (seen.has(p.name)) return { ok: false, code: "bundle_malformed" };
      seen.add(p.name);
    }
  }

  const msg = bundleSignatureMessage(version, policy, profilesForSig);
  let sig: Uint8Array;
  try {
    sig = b64ToBytes(signature);
  } catch {
    return { ok: false, code: "bad_signature" };
  }
  let verified = false;
  for (const keyB64 of pinnedKeys) {
    try {
      const key = await crypto.subtle.importKey("raw", b64ToBytes(keyB64), { name: "Ed25519" }, false, ["verify"]);
      if (await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg)) {
        verified = true;
        break;
      }
    } catch {
      /* a malformed pinned key just doesn't match; try the next */
    }
  }
  if (!verified) return { ok: false, code: "bad_signature" };

  // Anti-rollback AFTER signature (a valid signature over an old version is still
  // a rollback attack; an invalid signature over a high version is just forged).
  //
  // STRICTLY less-than. `minVersion` is the last-ACCEPTED version, so a healthy
  // plane serves exactly it every time between policy changes. Rejecting that
  // would freeze the liveness clock and make every restart fall back to the
  // local policy — while re-accepting the version already in force is
  // idempotent and cannot re-widen anything.
  if (version < minVersion) return { ok: false, code: "stale_version" };

  return {
    ok: true,
    version,
    policyYaml: policy,
    digest: await bundleDigest(policy, profilesForSig),
    unchanged: version === minVersion,
    profiles: profilesForSig,
  };
}

export type { BundleDenyCode, BundleVerifyResult };
