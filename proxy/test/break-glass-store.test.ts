import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BreakGlassStore, BreakGlassError } from "../src/breakglass/store.ts";

describe("BreakGlassStore", () => {
  let dir: string;
  let path: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "grenz-bg-"));
    path = join(dir, "break-glass.json");
  });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  test("pull records scope, quorum, and puller; list returns it while live", () => {
    const s = new BreakGlassStore(path);
    const rec = s.pull({ agentId: "claude", actions: ["pr:merge"], quorum: 1, reason: "hotfix", pulledBy: "carol", ttlMs: 900_000, now: 1000 });
    expect(rec.id).toMatch(/^bg/);
    expect(rec.pulledBy).toBe("carol");
    expect(rec.quorum).toBe(1);
    expect(rec.expiresAt).toBe(1000 + 900_000);
    expect(s.list(2000).map((r) => r.id)).toEqual([rec.id]);
  });

  test("an expired window drops out of list", () => {
    const s = new BreakGlassStore(path);
    s.pull({ agentId: "claude", actions: ["pr:merge"], quorum: 1, reason: "x", pulledBy: "carol", ttlMs: 100, now: 1000 });
    expect(s.list(1_000_000)).toEqual([]);
  });

  test("persists across instances", () => {
    const s1 = new BreakGlassStore(path);
    const rec = s1.pull({ agentId: "claude", actions: ["*"], quorum: 2, reason: "x", pulledBy: "dave", ttlMs: 900_000, now: 1000 });
    const s2 = new BreakGlassStore(path);
    expect(s2.list(2000).map((r) => r.id)).toEqual([rec.id]);
  });

  test("a corrupt file throws on load (fail-closed)", async () => {
    await writeFile(path, "{ not json");
    expect(() => new BreakGlassStore(path)).toThrow(BreakGlassError);
  });

  test("atCapacity guards the active count", () => {
    const s = new BreakGlassStore(path, 1);
    s.pull({ agentId: "a", actions: ["x"], quorum: 1, reason: "r", pulledBy: "p", ttlMs: 900_000, now: 1000 });
    expect(s.atCapacity(2000)).toBe(true);
  });
});
