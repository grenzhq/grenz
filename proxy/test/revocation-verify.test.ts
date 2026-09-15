import { test, expect, describe } from "bun:test";
import { verifyRevocationSet, MAX_REVOKED_AGENTS } from "../src/revocation/verify.ts";
import { MAX_POLICY_VERSION } from "../src/distribution/verify.ts";
import { makeKey, signRevSet } from "./support/revocation-set.ts";

describe("verifyRevocationSet", () => {
  test("valid set -> ok, sorted+deduped, version, expiry", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["b", "a", "a"], 4, 1784500000);
    const r = await verifyRevocationSet(bundle, [publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(4);
      expect(r.revokedAgents).toEqual(["a", "b"]);
      expect(r.expiresAt).toBe(1784500000);
      expect(r.unchanged).toBe(false);
    }
  });

  test("empty set is valid (nobody revoked)", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, [], 2, null);
    const r = await verifyRevocationSet(bundle, [publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.revokedAgents).toEqual([]);
  });

  test("version == floor -> ok + unchanged (steady state)", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["a"], 5, null);
    const r = await verifyRevocationSet(bundle, [publicKeyB64], 5);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.unchanged).toBe(true);
  });

  test("version < floor -> stale_version", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["a"], 4, null);
    const r = await verifyRevocationSet(bundle, [publicKeyB64], 5);
    expect(r).toEqual({ ok: false, code: "stale_version" });
  });

  test("tampered membership -> bad_signature", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["a"], 3, null);
    const tampered = JSON.parse(bundle);
    tampered.revoked_agents = ["a", "c"]; // add a member the signer never signed
    const r = await verifyRevocationSet(JSON.stringify(tampered), [publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "bad_signature" });
  });

  test("wrong key -> bad_signature", async () => {
    const { privJwkKey } = await makeKey();
    const other = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["a"], 3, null);
    const r = await verifyRevocationSet(bundle, [other.publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "bad_signature" });
  });

  test("domain separation: revocation payload signed under the POLICY domain -> bad_signature", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const wrongDomain = await signRevSet(privJwkKey, ["a"], 3, null, "grenz-policy-signature-v1");
    const r = await verifyRevocationSet(wrongDomain, [publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "bad_signature" });
  });

  test("dual-key rotation: second pinned key verifies", async () => {
    const oldK = await makeKey();
    const newK = await makeKey();
    const bundle = await signRevSet(newK.privJwkKey, ["a"], 3, null);
    const r = await verifyRevocationSet(bundle, [oldK.publicKeyB64, newK.publicKeyB64], 0);
    expect(r.ok).toBe(true);
  });

  test("malformed JSON -> set_malformed", async () => {
    const { publicKeyB64 } = await makeKey();
    const r = await verifyRevocationSet("{not json", [publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "set_malformed" });
  });

  test("bad envelope shape -> set_malformed", async () => {
    const { publicKeyB64 } = await makeKey();
    const r = await verifyRevocationSet(JSON.stringify({ version: 1 }), [publicKeyB64], 0);
    expect(r).toEqual({ ok: false, code: "set_malformed" });
  });

  test("out-of-bounds version -> set_malformed", async () => {
    const { publicKeyB64 } = await makeKey();
    const r = await verifyRevocationSet(
      JSON.stringify({ version: MAX_POLICY_VERSION + 1, revoked_agents: [], signature: "AA==" }),
      [publicKeyB64],
      0,
    );
    expect(r).toEqual({ ok: false, code: "set_malformed" });
  });

  test("too many agents -> set_malformed", async () => {
    const { publicKeyB64 } = await makeKey();
    const agents = Array.from({ length: MAX_REVOKED_AGENTS + 1 }, (_, i) => `a${i}`);
    const r = await verifyRevocationSet(
      JSON.stringify({ version: 1, revoked_agents: agents, signature: "AA==" }),
      [publicKeyB64],
      0,
    );
    expect(r).toEqual({ ok: false, code: "set_malformed" });
  });
});
