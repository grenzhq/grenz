import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TokenStore, TokenStoreError } from "../src/admin/token-store.ts";
import { hashToken } from "../src/util/token.ts";

describe("TokenStore", () => {
  let dir: string;
  let path: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "grenz-tok-"));
    path = join(dir, "admin-tokens.json");
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  test("create -> resolve round-trips identity", async () => {
    const s = new TokenStore(path);
    const { token } = await s.create("alice", "approver", 1000);
    const id = s.resolve(await hashToken(token), 2000);
    expect(id).toEqual({ name: "alice", role: "approver", subject: null });
  });

  test("resolve returns null for an unknown hash", async () => {
    const s = new TokenStore(path);
    expect(s.resolve(await hashToken("nope"), 1000)).toBeNull();
  });

  test("a revoked token no longer resolves", async () => {
    const s = new TokenStore(path);
    const { token } = await s.create("bob", "admin", 1000);
    expect(s.revoke("bob", 2000)).toBe(true);
    expect(s.resolve(await hashToken(token), 3000)).toBeNull();
  });

  test("duplicate LIVE name is rejected; a revoked name may be reused", async () => {
    const s = new TokenStore(path);
    await s.create("carol", "viewer", 1000);
    await expect(s.create("carol", "admin", 1100)).rejects.toBeInstanceOf(TokenStoreError);
    s.revoke("carol", 1200);
    const { token } = await s.create("carol", "admin", 1300); // reuse after revoke
    expect(s.resolve(await hashToken(token), 1400)).toEqual({ name: "carol", role: "admin", subject: null });
  });

  test("list returns metadata WITHOUT the hash", async () => {
    const s = new TokenStore(path);
    await s.create("dave", "viewer", 1000);
    const rows = s.list();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.name).toBe("dave");
    expect(rows[0]!.role).toBe("viewer");
  });

  test("a corrupt file throws on load (fail-closed)", async () => {
    await writeFile(path, "{ not json");
    expect(() => new TokenStore(path)).toThrow(TokenStoreError);
  });

  test("persists across instances", async () => {
    const s1 = new TokenStore(path);
    const { token } = await s1.create("erin", "approver", 1000);
    const s2 = new TokenStore(path);
    expect(s2.resolve(await hashToken(token), 2000)).toEqual({ name: "erin", role: "approver", subject: null });
  });

  describe("short-lived tokens (expiry)", () => {
    // resolve() rejects a token past its absolute expiry. In the OSS build only
    // hand-minted (never-expiring) tokens exist, so seed an expiring record on
    // disk directly to keep the expiry branch covered.
    test("an expired token does not resolve; a live one does", async () => {
      const token = "grenz-adm_test_expiry";
      const rec = {
        name: "ci-short",
        role: "approver",
        tokenHash: await hashToken(token),
        createdAt: 1000,
        revokedAt: null,
        subject: null,
        expiresAt: 2000,
      };
      await writeFile(path, JSON.stringify({ version: 1, tokens: [rec] }));
      const s = new TokenStore(path);
      const id = await hashToken(token);
      expect(s.resolve(id, 1999)).not.toBeNull();
      expect(s.resolve(id, 2000)).toBeNull(); // exp <= now
      expect(s.resolve(id, 3000)).toBeNull();
    });
    test("hand-minted tokens resolve with subject: null", async () => {
      const s = new TokenStore(path);
      const { token } = await s.create("ops", "admin", 1000);
      expect(s.resolve(await hashToken(token), 1000)).toEqual({ name: "ops", role: "admin", subject: null });
    });
  });
});
