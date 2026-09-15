/**
 * The canonical signed form of a revocation set. The signature covers SET
 * semantics — the sorted, deduplicated member list plus the optional expiry —
 * not the byte encoding of the transmitted JSON. Signer and verifier both go
 * through here, so a re-serialized (pretty-printed or minified) envelope still
 * verifies, while any change to the membership does not.
 *
 * The domain string is DISTINCT from the policy bundle's precisely because the
 * signing key is shared: it makes a policy bundle unusable as a revocation set
 * and vice versa.
 */
export const REVOCATION_DOMAIN = "grenz-revocation-signature-v1";

export function canonicalRevocationPayload(agents: readonly string[], expiresAt: number | null): string {
  const sorted = [...new Set(agents)].sort();
  // Fixed key order (object-literal insertion order) → deterministic JSON.
  return JSON.stringify({ revoked_agents: sorted, expires_at: expiresAt });
}

export function revocationMessage(version: number, agents: readonly string[], expiresAt: number | null): Uint8Array {
  return new TextEncoder().encode(`${REVOCATION_DOMAIN}\n${version}\n${canonicalRevocationPayload(agents, expiresAt)}`);
}
