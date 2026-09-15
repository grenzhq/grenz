import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { RevocationStore, RevocationError } from "../src/revoke/store.ts";

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-rev-"));
  path = join(dir, "revocations.json");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("RevocationStore", () => {
  test("missing file → empty, nothing revoked", () => {
    const s = new RevocationStore(path);
    expect(s.isRevoked("claude-code")).toBe(false);
    expect(s.list()).toEqual([]);
  });

  test("revoke → isRevoked, and it persists across reopen", () => {
    const s = new RevocationStore(path);
    s.revoke("claude-code", "risk:high", 1000);
    expect(s.isRevoked("claude-code")).toBe(true);
    // A fresh instance (i.e. a proxy restart) still sees it.
    const reopened = new RevocationStore(path);
    expect(reopened.isRevoked("claude-code")).toBe(true);
    expect(reopened.get("claude-code")?.reason).toBe("risk:high");
    expect(reopened.get("claude-code")?.ts).toBe(1000);
  });

  test("restore lifts it, persists, and returns whether it existed", () => {
    const s = new RevocationStore(path);
    s.revoke("a", "x", 1);
    expect(s.restore("a")).toBe(true);
    expect(s.restore("a")).toBe(false); // idempotent
    expect(new RevocationStore(path).isRevoked("a")).toBe(false);
  });

  test("list is newest-first", () => {
    const s = new RevocationStore(path);
    s.revoke("a", "x", 1);
    s.revoke("b", "y", 2);
    expect(s.list().map((r) => r.agentId)).toEqual(["b", "a"]);
  });

  test("revoke is idempotent per agent (updates reason + ts)", () => {
    const s = new RevocationStore(path);
    s.revoke("a", "first", 1);
    s.revoke("a", "second", 2);
    expect(s.list().length).toBe(1);
    expect(s.get("a")?.reason).toBe("second");
    expect(s.get("a")?.ts).toBe(2);
  });

  test("reason is bounded (no unbounded blob on disk)", () => {
    const s = new RevocationStore(path);
    s.revoke("a", "z".repeat(500), 1);
    expect(s.get("a")!.reason.length).toBeLessThanOrEqual(200);
  });

  test("corrupt file throws RevocationError (fail closed)", () => {
    writeFileSync(path, "{ not json");
    expect(() => new RevocationStore(path)).toThrow(RevocationError);
  });

  test("malformed-but-valid-JSON file throws (missing `revoked`)", () => {
    writeFileSync(path, JSON.stringify({ version: 1 }));
    expect(() => new RevocationStore(path)).toThrow(RevocationError);
  });

  test("reload picks up an out-of-band write (the offline CLI path)", () => {
    const proxySide = new RevocationStore(path);
    expect(proxySide.isRevoked("a")).toBe(false);
    // Simulate `grenz revoke` writing the file while the proxy holds its own
    // instance — reload() is how the file becomes authoritative again.
    new RevocationStore(path).revoke("a", "cli", 5);
    proxySide.reload();
    expect(proxySide.isRevoked("a")).toBe(true);
  });
});
