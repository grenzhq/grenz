import { test, expect, describe } from "bun:test";
import { generateSigningKeypair, signBundle } from "../src/distribution/keypair.ts";
import { verifyPolicyBundle } from "../src/distribution/verify.ts";

const YAML = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;

describe("keypair + signBundle", () => {
  test("keygen produces a keypair that signs a verifiable bundle", async () => {
    const kp = await generateSigningKeypair();
    expect(kp.publicKeyB64.length).toBeGreaterThan(0);
    const bundle = await signBundle(YAML, 2, kp.privateKeyB64, null);
    const r = await verifyPolicyBundle(bundle, [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.version).toBe(2);
  });
  test("a signature from key A does not verify under key B", async () => {
    const a = await generateSigningKeypair();
    const b = await generateSigningKeypair();
    const bundle = await signBundle(YAML, 1, a.privateKeyB64, null);
    expect(await verifyPolicyBundle(bundle, [b.publicKeyB64], 0)).toEqual({ ok: false, code: "bad_signature" });
  });
});

test("signBundle(null) emits a v1 bundle (no profiles field)", async () => {
  const kp = await generateSigningKeypair();
  expect("profiles" in JSON.parse(await signBundle("grants: []\n", 1, kp.privateKeyB64, null))).toBe(false);
});
test("signBundle([]) emits a v2 clear bundle", async () => {
  const kp = await generateSigningKeypair();
  expect(JSON.parse(await signBundle("grants: []\n", 1, kp.privateKeyB64, [])).profiles).toEqual([]);
});
test("signBundle validates entries at sign time (bad name throws)", async () => {
  const kp = await generateSigningKeypair();
  await expect(signBundle("grants: []\n", 1, kp.privateKeyB64, [{ name: "Bad Name", policy: "x" }])).rejects.toThrow();
});
test("signBundle rejects duplicate names", async () => {
  const kp = await generateSigningKeypair();
  await expect(
    signBundle("grants: []\n", 1, kp.privateKeyB64, [
      { name: "ci", policy: "x" },
      { name: "ci", policy: "y" },
    ]),
  ).rejects.toThrow();
});
