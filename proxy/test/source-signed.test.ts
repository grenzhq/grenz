import { test, expect, describe, afterEach } from "bun:test";
import { fetchSignedPolicy, MAX_SIGNED_BODY_BYTES } from "../src/policy/source.ts";
import { generateSigningKeypair, signBundle } from "../src/distribution/keypair.ts";
import type { ProfileEntry } from "../src/policy/profile-entry.ts";

let server: ReturnType<typeof Bun.serve> | null = null;
afterEach(() => { server?.stop(true); server = null; });
const YAML = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;

describe("fetchSignedPolicy", () => {
  test("valid signed bundle -> compiled policy + version + yaml", async () => {
    const kp = await generateSigningKeypair();
    const bundle = await signBundle(YAML, 4, kp.privateKeyB64, null);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "org-tok", [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.version).toBe(4);
      expect(r.policyYaml).toBe(YAML);
      expect(r.digest).toMatch(/^[0-9a-f]{12}$/);
      expect(r.policy.grants.size).toBeGreaterThan(0);
    }
  });
  test("bad signature -> error, no policy", async () => {
    const kp = await generateSigningKeypair();
    const other = await generateSigningKeypair();
    const bundle = await signBundle(YAML, 4, kp.privateKeyB64, null);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "t", [other.publicKeyB64], 0);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("signature invalid");
  });
  test("stale version -> error", async () => {
    const kp = await generateSigningKeypair();
    const bundle = await signBundle(YAML, 2, kp.privateKeyB64, null);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "t", [kp.publicKeyB64], 5);
    expect(r).toEqual({ ok: false, error: expect.stringContaining("stale") });
  });
  test("unreachable -> error", async () => {
    const kp = await generateSigningKeypair();
    const r = await fetchSignedPolicy("http://127.0.0.1:1/b", "t", [kp.publicKeyB64], 0);
    expect(r.ok).toBe(false);
  });
  test("non-200 from the plane -> error", async () => {
    const kp = await generateSigningKeypair();
    server = Bun.serve({ port: 0, fetch: () => new Response("nope", { status: 503 }) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "t", [kp.publicKeyB64], 0);
    expect(r).toEqual({ ok: false, error: expect.stringContaining("503") });
  });

  test("body over MAX_SIGNED_BODY_BYTES -> rejected as too large, never parsed/verified", async () => {
    const kp = await generateSigningKeypair();
    const oversized = "x".repeat(MAX_SIGNED_BODY_BYTES + 1);
    server = Bun.serve({ port: 0, fetch: () => new Response(oversized) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "t", [kp.publicKeyB64], 0);
    expect(r.ok).toBe(false);
    // "too large" is distinct from the "malformed bundle" message verifyPolicyBundle
    // would produce on this same non-JSON body -- proving the cap fires first.
    if (!r.ok) expect(r.error).toMatch(/too large/);
  });

  test("valid v2 bundle with profiles -> result.profiles deep-equals the signed profiles", async () => {
    const kp = await generateSigningKeypair();
    const profiles: readonly ProfileEntry[] = [
      { name: "reader", policy: "agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]" },
      { name: "writer", policy: "agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:write]" },
    ];
    const bundle = await signBundle(YAML, 4, kp.privateKeyB64, profiles);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "org-tok", [kp.publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.profiles).toEqual(profiles);
  });

  test("body exactly MAX_SIGNED_BODY_BYTES is not rejected for size", async () => {
    const kp = await generateSigningKeypair();
    const boundary = "x".repeat(MAX_SIGNED_BODY_BYTES);
    server = Bun.serve({ port: 0, fetch: () => new Response(boundary) });
    const r = await fetchSignedPolicy(`http://127.0.0.1:${server.port}/b`, "t", [kp.publicKeyB64], 0);
    expect(r.ok).toBe(false);
    // Falls through to verification and fails there (not valid JSON), NOT on size.
    if (!r.ok) expect(r.error).not.toMatch(/too large/);
  });
});
