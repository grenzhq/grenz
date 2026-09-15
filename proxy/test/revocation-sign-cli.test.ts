import { test, expect, describe, afterEach } from "bun:test";
import { rmSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseAgentList, signRevocationText } from "../src/cli/revocation-sign.ts";
import { generateSigningKeypair } from "../src/distribution/keypair.ts";
import { verifyRevocationSet } from "../src/revocation/verify.ts";

let keyFile = "";
afterEach(() => {
  if (keyFile && existsSync(keyFile)) rmSync(keyFile);
  keyFile = "";
});

describe("parseAgentList", () => {
  test("splits on commas/space/newlines, dedupes, sorts", () => {
    expect(parseAgentList("b, a\nc  a,,")).toEqual(["a", "b", "c"]);
  });
  test("empty input -> empty list (publishable)", () => {
    expect(parseAgentList("  \n ")).toEqual([]);
  });
});

describe("signRevocationText round-trip", () => {
  async function writeKey(): Promise<{ pub: string }> {
    const kp = await generateSigningKeypair();
    keyFile = join(tmpdir(), `rev-key-${Math.floor(performance.now() * 1000)}`);
    writeFileSync(keyFile, kp.privateKeyB64, { mode: 0o600 });
    return { pub: kp.publicKeyB64 };
  }

  test("signs a set that verifies, sorted, with expiry", async () => {
    const { pub } = await writeKey();
    const bundle = await signRevocationText(["z", "a"], keyFile, 3, 3600, 1_000_000);
    const r = await verifyRevocationSet(bundle, [pub], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(3);
      expect(r.revokedAgents).toEqual(["a", "z"]);
      expect(r.expiresAt).toBe(1_003_600); // now + expiresIn
    }
  });

  test("empty set is signable and verifiable", async () => {
    const { pub } = await writeKey();
    const bundle = await signRevocationText([], keyFile, 2, null, 1_000_000);
    const r = await verifyRevocationSet(bundle, [pub], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.revokedAgents).toEqual([]);
      expect(r.expiresAt).toBeNull();
    }
  });
});
