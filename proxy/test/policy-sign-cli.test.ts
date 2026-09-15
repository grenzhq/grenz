import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keygenText, keygenToFile, signText, nextVersionOk, runPolicySign } from "../src/cli/policy-sign.ts";
import { verifyPolicyBundle } from "../src/distribution/verify.ts";
import { generateSigningKeypair } from "../src/distribution/keypair.ts";
import type { ParsedArgs } from "../src/cli/args.ts";

const YAML = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;

describe("policy sign CLI core", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "grenz-sign-")); });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  test("keygenText prints a private and public key, and warns about the private one", async () => {
    const out = await keygenText();
    expect(out).toMatch(/private key/i);
    expect(out).toMatch(/public key/i);
    expect(out).toMatch(/NEVER/);
  });

  test("signText emits a bundle that verifies under the matching public key", async () => {
    const kp = await generateSigningKeypair();
    const keyPath = join(dir, "key");
    await writeFile(keyPath, kp.privateKeyB64);
    const policyPath = join(dir, "policy.yaml");
    await writeFile(policyPath, YAML);
    const bundle = await signText(policyPath, keyPath, 3, null);
    const r = await verifyPolicyBundle(bundle, [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(3);
      expect(r.policyYaml).toBe(YAML);
    }
  });

  test("signText tolerates a trailing newline in the key file", async () => {
    const kp = await generateSigningKeypair();
    const keyPath = join(dir, "key");
    await writeFile(keyPath, `${kp.privateKeyB64}\n`);
    const policyPath = join(dir, "policy.yaml");
    await writeFile(policyPath, YAML);
    const r = await verifyPolicyBundle(await signText(policyPath, keyPath, 1, null), [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
  });

  test("keygen --out writes a 0600 key file that sign can actually read", async () => {
    // Redirecting the human-readable keygen output into a file would include the
    // comment block and fail to parse -- --out writes the bare base64 key.
    const keyPath = join(dir, "signing.key");
    const out = await keygenToFile(keyPath);
    const pub = (out.match(/public key:\s*(\S+)/) ?? [])[1] ?? "";
    expect(pub.length).toBeGreaterThan(0);
    expect(out).not.toMatch(/private key:/); // the secret is in the file, not stdout
    expect((statSync(keyPath).mode & 0o777).toString(8)).toBe("600");

    const policyPath = join(dir, "policy.yaml");
    await writeFile(policyPath, YAML);
    const r = await verifyPolicyBundle(await signText(policyPath, keyPath, 5, null), [pub], 0);
    expect(r.ok).toBe(true);
  });

  test("signText refuses a non-compiling policy (never sign a broken policy)", async () => {
    const kp = await generateSigningKeypair();
    const keyPath = join(dir, "key");
    await writeFile(keyPath, kp.privateKeyB64);
    const policyPath = join(dir, "p.yaml");
    await writeFile(policyPath, "this: is not: valid: policy");
    await expect(signText(policyPath, keyPath, 1, null)).rejects.toThrow(/does not compile/);
  });

  test("signText with a profile → verify returns that profile", async () => {
    const kp = await generateSigningKeypair();
    const keyPath = join(dir, "key");
    await writeFile(keyPath, kp.privateKeyB64);
    const policyPath = join(dir, "policy.yaml");
    await writeFile(policyPath, YAML);
    const ciYaml = `agent: ci\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;

    const bundle = await signText(policyPath, keyPath, 3, [{ name: "ci", policy: ciYaml }]);
    const r = await verifyPolicyBundle(bundle, [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(3);
      expect(r.profiles).toEqual([{ name: "ci", policy: ciYaml }]);
    }
  });

  test("signText(null) → v1 bundle (verify profiles === null)", async () => {
    const kp = await generateSigningKeypair();
    const keyPath = join(dir, "key");
    await writeFile(keyPath, kp.privateKeyB64);
    const policyPath = join(dir, "policy.yaml");
    await writeFile(policyPath, YAML);

    const bundle = await signText(policyPath, keyPath, 4, null);
    expect(bundle).not.toMatch(/"profiles"/);
    const r = await verifyPolicyBundle(bundle, [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.profiles).toBeNull();
  });

  test("signText([]) → v2 clear (verify profiles === [])", async () => {
    const kp = await generateSigningKeypair();
    const keyPath = join(dir, "key");
    await writeFile(keyPath, kp.privateKeyB64);
    const policyPath = join(dir, "policy.yaml");
    await writeFile(policyPath, YAML);

    const bundle = await signText(policyPath, keyPath, 5, []);
    const r = await verifyPolicyBundle(bundle, [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.profiles).toEqual([]);
  });

  test("nextVersionOk enforces strictly-greater unless forced", () => {
    expect(nextVersionOk(5, 4, false)).toBe(true);
    expect(nextVersionOk(5, 5, false)).toBe(false);
    expect(nextVersionOk(5, 5, true)).toBe(true);
    expect(nextVersionOk(5, null, false)).toBe(true);
  });
});

// runPolicySign, called directly (no subprocess/argv) — the deny-by-default
// paths CLAUDE.md's Definition of Done requires a test for: error-on-omission
// against a declared policy_profiles set, and the version-bump guard.
describe("grenz policy sign CLI (runPolicySign)", () => {
  let tempDirs: string[] = [];

  beforeEach(() => {
    tempDirs = [];
  });
  afterEach(async () => {
    for (const d of tempDirs) await rm(d, { recursive: true, force: true });
  });

  function signArgs(positionals: string[], flags: Record<string, string | boolean> = {}): ParsedArgs {
    return { positionals, flags: new Map(Object.entries(flags)) };
  }

  async function captureIO(fn: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
    const out: string[] = [];
    const err: string[] = [];
    const ow = process.stdout.write;
    const ew = process.stderr.write;
    process.stdout.write = ((s: string | Uint8Array) => (out.push(String(s)), true)) as typeof process.stdout.write;
    process.stderr.write = ((s: string | Uint8Array) => (err.push(String(s)), true)) as typeof process.stderr.write;
    try {
      const code = await fn();
      return { code, out: out.join(""), err: err.join("") };
    } finally {
      process.stdout.write = ow;
      process.stderr.write = ew;
    }
  }

  async function seedHome(
    withProfiles: boolean,
  ): Promise<{ home: string; keyPath: string; policyPath: string; publicKeyB64: string }> {
    const home = await mkdtemp(join(tmpdir(), "grenz-signcli-"));
    tempDirs.push(home);
    const lines = ["agents:", "  - id: a", `    token_hash: "${"0".repeat(64)}"`];
    if (withProfiles) lines.push("policy_profiles:", "  ci:");
    await writeFile(join(home, "grenz.yaml"), lines.join("\n") + "\n");
    const policyPath = join(home, "policy.yaml");
    await writeFile(policyPath, YAML);
    const kp = await generateSigningKeypair();
    const keyPath = join(home, "signing.key");
    await writeFile(keyPath, kp.privateKeyB64);
    return { home, keyPath, policyPath, publicKeyB64: kp.publicKeyB64 };
  }

  test("declared policy_profiles + no --profile/--clear-profiles -> deny-by-default (exit 1, no bundle)", async () => {
    const { home, keyPath, policyPath } = await seedHome(true);
    const { code, out, err } = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "3" })),
    );
    expect(code).toBe(1);
    expect(out).toBe(""); // no bundle emitted to stdout
    expect(err).toMatch(/policy_profiles/);
  });

  test("no policy_profiles + no --profile -> v1 bundle, exit 0", async () => {
    const { home, keyPath, policyPath, publicKeyB64 } = await seedHome(false);
    const { code, out } = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "1" })),
    );
    expect(code).toBe(0);
    const r = await verifyPolicyBundle(out.trim(), [publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.profiles).toBeNull();
  });

  test("no grenz.yaml at all (off-proxy/CI) + no --profile -> v1 bundle, exit 0", async () => {
    // `grenz policy sign` runs in CI with only policy.yaml + the key; a missing
    // grenz.yaml must NOT throw ConfigError — it means "no profiles declared".
    const home = await mkdtemp(join(tmpdir(), "grenz-signcli-nocfg-"));
    tempDirs.push(home);
    const policyPath = join(home, "policy.yaml");
    await writeFile(policyPath, YAML);
    const kp = await generateSigningKeypair();
    const keyPath = join(home, "signing.key");
    await writeFile(keyPath, kp.privateKeyB64);

    const { code, out } = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "1" })),
    );
    expect(code).toBe(0);
    const r = await verifyPolicyBundle(out.trim(), [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.profiles).toBeNull(); // valid v1 bundle
  });

  test("re-signing the same --version is refused; --force-version overrides", async () => {
    const { home, keyPath, policyPath } = await seedHome(false);

    const first = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "5" })),
    );
    expect(first.code).toBe(0);
    expect(readFileSync(join(home, "last-signed-version"), "utf8").trim()).toBe("5");

    const second = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "5" })),
    );
    expect(second.code).toBe(1);
    expect(second.err).toMatch(/--force-version/);

    const third = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "5", "force-version": true })),
    );
    expect(third.code).toBe(0);
  });

  test("corrupt last-signed-version fails closed (exit 1)", async () => {
    const { home, keyPath, policyPath } = await seedHome(false);
    await writeFile(join(home, "last-signed-version"), "not-a-number");
    const { code, err } = await captureIO(() =>
      runPolicySign(signArgs(["sign", policyPath], { home, key: keyPath, version: "2" })),
    );
    expect(code).toBe(1);
    expect(err).toMatch(/corrupt/);
  });
});
