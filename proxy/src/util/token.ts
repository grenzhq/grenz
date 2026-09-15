/**
 * GRENZ_TOKEN helpers.
 *
 * The agent is issued a GRENZ_TOKEN and nothing else. Grenz stores only the
 * token's SHA-256 hash (config is therefore not secret); the plaintext is shown
 * once at `grenz init` time. Comparison at request time is constant-time.
 *
 * Uses Web Crypto only (no node: deps) so it compiles cleanly into the binary.
 */

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Generate a fresh token: `<prefix>_` + 256 bits of base64url randomness. */
export function generateToken(prefix = "grenz"): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `${prefix}_${toBase64Url(bytes)}`;
}

/** SHA-256 of the token, hex-encoded. Stored in config; safe to persist. */
export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(token));
  return toHex(new Uint8Array(digest));
}

/** Constant-time string comparison over equal-length hex digests. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
