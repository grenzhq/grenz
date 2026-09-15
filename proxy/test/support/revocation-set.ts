import { makeKey } from "./policy-bundle.ts";
import { canonicalRevocationPayload } from "../../src/revocation/canonical.ts";

export { makeKey };

/**
 * Sign a revocation-set envelope. `domain` defaults to the revocation domain;
 * pass the policy domain to construct a wrong-domain signature for the
 * domain-separation test.
 */
export async function signRevSet(
  privKey: CryptoKey,
  agents: string[],
  version: number,
  expiresAt: number | null,
  domain = "grenz-revocation-signature-v1",
): Promise<string> {
  const sorted = [...new Set(agents)].sort();
  const msg = new TextEncoder().encode(`${domain}\n${version}\n${canonicalRevocationPayload(sorted, expiresAt)}`);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privKey, msg);
  const env: Record<string, unknown> = {
    version,
    revoked_agents: sorted,
    signature: Buffer.from(new Uint8Array(sig)).toString("base64"),
  };
  if (expiresAt !== null) env.expires_at = expiresAt;
  return JSON.stringify(env, null, 2);
}
