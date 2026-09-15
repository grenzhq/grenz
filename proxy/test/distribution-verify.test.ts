import { test, expect, describe } from "bun:test";
import { verifyPolicyBundle } from "../src/distribution/verify.ts";
import { makeKey, signWith } from "./support/policy-bundle.ts";
import { signBundle, generateSigningKeypair } from "../src/distribution/keypair.ts";
import { bundleSignatureMessage } from "../src/distribution/message.ts";

const YAML = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;

describe("verifyPolicyBundle", () => {
  test("valid bundle -> ok with version + digest", async () => {
    const k = await makeKey();
    const r = await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 5), [k.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(5);
      expect(r.policyYaml).toBe(YAML);
      expect(r.digest).toMatch(/^[0-9a-f]{12}$/);
    }
  });
  test("tampered policy -> bad_signature", async () => {
    const k = await makeKey();
    const bundle = JSON.parse(await signWith(k.privJwkKey, YAML, 5));
    bundle.policy = YAML + "\n# sneaky";
    const r = await verifyPolicyBundle(JSON.stringify(bundle), [k.publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "bad_signature" });
  });
  test("tampered version -> bad_signature (version is signed)", async () => {
    const k = await makeKey();
    const bundle = JSON.parse(await signWith(k.privJwkKey, YAML, 5));
    bundle.version = 999;
    const r = await verifyPolicyBundle(JSON.stringify(bundle), [k.publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "bad_signature" });
  });
  test("wrong key -> bad_signature", async () => {
    const k = await makeKey();
    const other = await makeKey();
    const r = await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 5), [other.publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "bad_signature" });
  });
  test("version < floor -> stale_version (anti-rollback)", async () => {
    const k = await makeKey();
    const r = await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 2), [k.publicKeyB64], 3);
    expect(r).toEqual({ ok: false, code: "stale_version" });
  });
  test("version == floor -> ok but flagged unchanged (re-serving the current policy is not a rollback)", async () => {
    // The floor is the LAST-ACCEPTED version, so a healthy plane serves this
    // every time between policy changes. Rejecting it would freeze the liveness
    // clock and make a restart fall back to the local policy.
    const k = await makeKey();
    const r = await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 3), [k.publicKeyB64], 3);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(3);
      expect(r.unchanged).toBe(true);
    }
  });
  test("a newer version is not flagged unchanged", async () => {
    const k = await makeKey();
    const r = await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 4), [k.publicKeyB64], 3);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.unchanged).toBe(false);
  });
  test("version 0 or negative is rejected as malformed (versions start at 1)", async () => {
    const k = await makeKey();
    expect(await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 0), [k.publicKeyB64], 0)).toEqual({
      ok: false,
      code: "bundle_malformed",
    });
    expect(await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, -5), [k.publicKeyB64], 0)).toEqual({
      ok: false,
      code: "bundle_malformed",
    });
  });
  test("an absurd version is refused so it cannot permanently exhaust the floor", async () => {
    // A fat-fingered epoch-nanos or run-id would otherwise become the floor and
    // block every future policy version on that proxy, forever.
    const k = await makeKey();
    expect(await verifyPolicyBundle(await signWith(k.privJwkKey, YAML, 1e21), [k.publicKeyB64], 0)).toEqual({
      ok: false,
      code: "bundle_malformed",
    });
  });
  test("dual-key: a second pinned key verifies (rotation)", async () => {
    const oldK = await makeKey();
    const newK = await makeKey();
    const r = await verifyPolicyBundle(await signWith(newK.privJwkKey, YAML, 6), [oldK.publicKeyB64, newK.publicKeyB64], 0);
    expect(r.ok).toBe(true);
  });
  test("malformed JSON -> bundle_malformed", async () => {
    const k = await makeKey();
    expect(await verifyPolicyBundle("{not json", [k.publicKeyB64], 0)).toEqual({ ok: false, code: "bundle_malformed" });
  });
  test("bad envelope shape -> bundle_malformed", async () => {
    const k = await makeKey();
    expect(await verifyPolicyBundle(JSON.stringify({ version: "x" }), [k.publicKeyB64], 0)).toEqual({ ok: false, code: "bundle_malformed" });
  });
});

async function keys() {
  const kp = await generateSigningKeypair();
  return { priv: kp.privateKeyB64, pub: [kp.publicKeyB64] };
}
const DEFV2 = "agent: root\non_behalf_of: user\ngrants: []\n";
const PROFS = [{ name: "ci", policy: "agent: a\non_behalf_of: u\ngrants: []\n" }];

test("a v2 bundle verifies and returns its profiles", async () => {
  const { priv, pub } = await keys();
  const r = await verifyPolicyBundle(await signBundle(DEFV2, 5, priv, PROFS), pub, 0);
  expect(r.ok).toBe(true);
  if (r.ok) expect(r.profiles).toEqual(PROFS);
});
test("a v1 bundle verifies; profiles === null", async () => {
  const { priv, pub } = await keys();
  const r = await verifyPolicyBundle(await signBundle(DEFV2, 5, priv, null), pub, 0);
  expect(r.ok).toBe(true);
  if (r.ok) expect(r.profiles).toBeNull();
});
test("stripping profiles from a v2 bundle → bad_signature", async () => {
  const { priv, pub } = await keys();
  const b = JSON.parse(await signBundle(DEFV2, 5, priv, PROFS)); delete b.profiles;
  const r = await verifyPolicyBundle(JSON.stringify(b), pub, 0);
  expect(r.ok).toBe(false); if (!r.ok) expect(r.code).toBe("bad_signature");
});
test("stripping an empty profiles:[] (clear) → bad_signature", async () => {
  const { priv, pub } = await keys();
  const b = JSON.parse(await signBundle(DEFV2, 5, priv, [])); delete b.profiles;
  const r = await verifyPolicyBundle(JSON.stringify(b), pub, 0);
  expect(r.ok).toBe(false); if (!r.ok) expect(r.code).toBe("bad_signature");
});
test("tampering a profile policy byte → bad_signature", async () => {
  const { priv, pub } = await keys();
  const b = JSON.parse(await signBundle(DEFV2, 5, priv, PROFS)); b.profiles[0].policy += " ";
  const r = await verifyPolicyBundle(JSON.stringify(b), pub, 0);
  expect(r.ok).toBe(false); if (!r.ok) expect(r.code).toBe("bad_signature");
});
test("a duplicate profile name → bundle_malformed (build the bundle directly, bypassing signBundle's guard)", async () => {
  // signBundle rejects duplicates at sign time, so forge the signed bundle by hand
  // to exercise the VERIFIER's duplicate guard.
  const kp = await generateSigningKeypair();
  const dup = [{ name: "ci", policy: "grants: []\n" }, { name: "ci", policy: "grants: []\n" }];
  const key = await crypto.subtle.importKey("pkcs8", new Uint8Array(Buffer.from(kp.privateKeyB64, "base64")), { name: "Ed25519" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, bundleSignatureMessage(5, DEFV2, dup));
  const bundle = JSON.stringify({ version: 5, policy: DEFV2, profiles: dup, signature: Buffer.from(new Uint8Array(sig)).toString("base64") });
  const r = await verifyPolicyBundle(bundle, [kp.publicKeyB64], 0);
  expect(r.ok).toBe(false); if (!r.ok) expect(r.code).toBe("bundle_malformed");
});
test("anti-rollback still fires with profiles present", async () => {
  const { priv, pub } = await keys();
  const r = await verifyPolicyBundle(await signBundle(DEFV2, 3, priv, PROFS), pub, 5);
  expect(r.ok).toBe(false); if (!r.ok) expect(r.code).toBe("stale_version");
});
