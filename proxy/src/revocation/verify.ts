/**
 * Pure verification of a signed revocation set (a CRL — current-state, not an
 * event stream). Async only for WebCrypto; does NO network. Runs at LOAD time
 * (startup + background refresh), never on the request path. Verifies a control
 * INPUT (who is cut off now), NOT tamper-evident logging. Every failure is a
 * fixed code carrying no key bytes or agent-supplied content.
 */
import { z } from "zod";
import { MAX_POLICY_VERSION } from "../distribution/verify.ts";
import { revocationMessage } from "./canonical.ts";
import type { RevocationVerifyResult } from "./types.ts";

/** Defence-in-depth cap: a signature-verified set can only come from the org
 *  signer, but an unbounded array would still let a malformed pre-verify parse
 *  allocate without limit. */
export const MAX_REVOKED_AGENTS = 100_000;

const setSchema = z
  .object({
    version: z.number().int().min(1).max(MAX_POLICY_VERSION),
    revoked_agents: z.array(z.string().min(1).max(256)).max(MAX_REVOKED_AGENTS),
    expires_at: z.number().int().positive().optional(),
    signature: z.string(),
  })
  .strict();

function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export async function verifyRevocationSet(
  text: string,
  pinnedKeys: string[],
  minVersion: number,
): Promise<RevocationVerifyResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, code: "set_malformed" };
  }
  const env = setSchema.safeParse(parsed);
  if (!env.success) return { ok: false, code: "set_malformed" };
  const { version, revoked_agents, expires_at, signature } = env.data;
  const expiresAt = expires_at ?? null;

  const msg = revocationMessage(version, revoked_agents, expiresAt);
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

  // Anti-rollback AFTER signature. STRICTLY less-than: minVersion is the
  // last-ACCEPTED version, so a healthy plane re-serves exactly it between
  // changes. Rejecting equal would freeze the liveness clock; re-accepting the
  // set already in force is idempotent (identical signed content).
  if (version < minVersion) return { ok: false, code: "stale_version" };

  return {
    ok: true,
    version,
    revokedAgents: [...new Set(revoked_agents)].sort(),
    expiresAt,
    unchanged: version === minVersion,
  };
}
