/**
 * Ed25519 key + bundle-signing helpers for `grenz policy keygen`/`sign` and
 * `grenz revocations sign`. Runs on the customer's CI / admin workstation —
 * NEVER imported by the proxy runtime. The private key is exported pkcs8
 * (base64); the public key raw (base64).
 */
import { revocationMessage } from "../revocation/canonical.ts";
import { bundleSignatureMessage } from "./message.ts";
import { profileEntrySchema, type ProfileEntry } from "../policy/profile-entry.ts";

export async function generateSigningKeypair(): Promise<{ privateKeyB64: string; publicKeyB64: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const pub = await crypto.subtle.exportKey("raw", kp.publicKey);
  return {
    privateKeyB64: Buffer.from(new Uint8Array(priv)).toString("base64"),
    publicKeyB64: Buffer.from(new Uint8Array(pub)).toString("base64"),
  };
}

export async function signBundle(
  policyYaml: string,
  version: number,
  privateKeyB64: string,
  profiles: readonly ProfileEntry[] | null, // NO default: caller states v1 (null) or v2 (array, incl [])
): Promise<string> {
  if (profiles !== null) {
    const names = new Set<string>();
    for (const p of profiles) {
      profileEntrySchema.parse(p); // throws on bad name/shape/oversize
      if (names.has(p.name)) throw new Error(`duplicate profile "${p.name}"`);
      names.add(p.name);
    }
  }
  const key = await crypto.subtle.importKey(
    "pkcs8",
    new Uint8Array(Buffer.from(privateKeyB64, "base64")),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, bundleSignatureMessage(version, policyYaml, profiles));
  const env: Record<string, unknown> = { version, policy: policyYaml };
  if (profiles !== null) env.profiles = profiles;
  env.signature = Buffer.from(new Uint8Array(sig)).toString("base64");
  return JSON.stringify(env, null, 2);
}

/**
 * Sign a revocation SET into a distributable envelope. CLI-only; the private key
 * never goes on a proxy or the plane. `expiresAt` (epoch seconds) is the signed
 * freshness window (CRL nextUpdate); null omits it. The envelope's revoked_agents
 * are sorted + deduped so the artifact is canonical. Shares the canonical
 * message with the verifier, so signer and verifier can never drift.
 */
export async function signRevocationSet(
  agents: string[],
  version: number,
  expiresAt: number | null,
  privateKeyB64: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    new Uint8Array(Buffer.from(privateKeyB64, "base64")),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const sorted = [...new Set(agents)].sort();
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, revocationMessage(version, sorted, expiresAt));
  const env: Record<string, unknown> = {
    version,
    revoked_agents: sorted,
    signature: Buffer.from(new Uint8Array(sig)).toString("base64"),
  };
  if (expiresAt !== null) env.expires_at = expiresAt;
  return JSON.stringify(env, null, 2);
}
