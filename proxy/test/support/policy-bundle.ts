/** Test-only: Ed25519 keygen + bundle signing mirroring the real signer. */
export async function makeKey(): Promise<{ privJwkKey: CryptoKey; publicKeyB64: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { privJwkKey: kp.privateKey, publicKeyB64: Buffer.from(new Uint8Array(raw)).toString("base64") };
}
export async function signWith(privKey: CryptoKey, policyYaml: string, version: number): Promise<string> {
  const msg = new TextEncoder().encode(`grenz-policy-signature-v1\n${version}\n${policyYaml}`);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privKey, msg);
  return JSON.stringify({ version, policy: policyYaml, signature: Buffer.from(new Uint8Array(sig)).toString("base64") });
}
