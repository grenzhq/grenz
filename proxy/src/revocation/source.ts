/**
 * Pull + verify a signed revocation set. Mirrors fetchSignedPolicy: 5s timeout,
 * fail on non-200 / unreachable, verify against pinned keys with an anti-rollback
 * floor. LOAD-time only; nothing on the request path touches a signature.
 */
import { verifyRevocationSet } from "./verify.ts";

const FETCH_TIMEOUT_MS = 5000;

export type RevocationFetchResult =
  | {
      readonly ok: true;
      readonly version: number;
      readonly revokedAgents: readonly string[];
      readonly expiresAt: number | null;
      readonly unchanged: boolean;
    }
  | { readonly ok: false; readonly error: string };

export async function fetchRevocationSet(
  url: string,
  orgToken: string,
  pinnedKeys: string[],
  minVersion: number,
): Promise<RevocationFetchResult> {
  let text: string;
  try {
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${orgToken}` },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `revocation source returned ${res.status}` };
    text = await res.text();
  } catch {
    return { ok: false, error: "revocation source unreachable" };
  }
  const v = await verifyRevocationSet(text, pinnedKeys, minVersion);
  if (!v.ok) {
    const why =
      v.code === "stale_version"
        ? "stale (anti-rollback)"
        : v.code === "bad_signature"
          ? "signature invalid"
          : "malformed set";
    return { ok: false, error: `signed revocation set rejected: ${why}` };
  }
  return { ok: true, version: v.version, revokedAgents: v.revokedAgents, expiresAt: v.expiresAt, unchanged: v.unchanged };
}
