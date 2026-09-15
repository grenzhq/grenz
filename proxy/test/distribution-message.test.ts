import { test, expect } from "bun:test";
import { canonicalProfiles, bundleSignatureMessage, bundleDigest } from "../src/distribution/message.ts";
const dec = (u: Uint8Array) => new TextDecoder().decode(u);

test("canonicalProfiles is order-independent", () => {
  const a = canonicalProfiles([{ name: "b", policy: "y" }, { name: "a", policy: "x" }]);
  const b = canonicalProfiles([{ name: "a", policy: "x" }, { name: "b", policy: "y" }]);
  expect(a).toBe(b);
});
test("null selects v1; an array (incl empty) selects v2", () => {
  expect(dec(bundleSignatureMessage(3, "grants: []\n", null))).toBe("grenz-policy-signature-v1\n3\ngrants: []\n");
  expect(dec(bundleSignatureMessage(3, "P", []))).toBe("grenz-policy-signature-v2\n3\nP\n[]");
});
test("presence binds: [] and null never produce the same bytes (strip-empty downgrade)", () => {
  expect(dec(bundleSignatureMessage(1, "P", []))).not.toBe(dec(bundleSignatureMessage(1, "P", null)));
});
test("a newline/prefix in a policy cannot forge a v2 collision", () => {
  const m1 = dec(bundleSignatureMessage(1, "P", [{ name: "a", policy: "line1\nline2" }]));
  const m2 = dec(bundleSignatureMessage(1, "P\nline2", [{ name: "a", policy: "line1" }]));
  expect(m1).not.toBe(m2);
});
test("bundleDigest changes when a profile changes; absent vs empty differ", async () => {
  const d1 = await bundleDigest("P", [{ name: "ci", policy: "grants: []\n" }]);
  const d2 = await bundleDigest("P", [{ name: "ci", policy: "grants: [1]\n" }]);
  expect(d1).not.toBe(d2);
  expect(await bundleDigest("P", null)).not.toBe(await bundleDigest("P", []));
});
test("bundleDigest domain-separates: the old \\x00-join collision no longer holds", async () => {
  // Under the old `policyYaml + '\x00' + canonicalProfiles` join, a v1 policy that
  // literally ended with `\x00` + the canonical JSON hashed the same bytes as the
  // v2 (policy, profiles) split. The tagged, length-prefixed input breaks that.
  const v1 = await bundleDigest("X\x00" + '[["ci","y"]]', null);
  const v2 = await bundleDigest("X", [{ name: "ci", policy: "y" }]);
  expect(v1).not.toBe(v2);
});
