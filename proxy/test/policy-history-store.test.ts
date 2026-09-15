import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PolicyHistoryStore } from "../src/policy/history-store.ts";

let dir: string;
let histDir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-hist-"));
  histDir = join(dir, "policy-history");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("PolicyHistoryStore", () => {
  test("missing dir: list/read/latestHash don't throw", () => {
    const s = new PolicyHistoryStore(histDir);
    expect(s.list()).toEqual([]);
    expect(s.read(1)).toBeNull();
    expect(s.latestHash()).toBeNull();
    expect(existsSync(histDir)).toBe(false); // reading never creates the dir
  });

  test("first record creates dir + file and is listed", () => {
    const s = new PolicyHistoryStore(histDir);
    const r = s.record("policy A", 1000);
    expect(r.saved).toBe(true);
    expect(r.name).not.toBeNull();
    expect(existsSync(histDir)).toBe(true);
    const list = s.list();
    expect(list.length).toBe(1);
    expect(list[0]!.index).toBe(1);
    expect(list[0]!.bytes).toBe(Buffer.byteLength("policy A"));
  });

  test("identical consecutive record is a no-op", () => {
    const s = new PolicyHistoryStore(histDir);
    expect(s.record("same", 1000).saved).toBe(true);
    expect(s.record("same", 2000).saved).toBe(false);
    expect(s.list().length).toBe(1);
  });

  test("changed record adds another, newest first", () => {
    const s = new PolicyHistoryStore(histDir);
    s.record("v1", Date.UTC(2026, 0, 1, 0, 0, 0));
    s.record("v2", Date.UTC(2026, 0, 2, 0, 0, 0));
    const list = s.list();
    expect(list.length).toBe(2);
    expect(s.read(1)).toBe("v2"); // index 1 = newest
    expect(s.read(2)).toBe("v1");
    expect(s.read(3)).toBeNull();
    expect(s.latestHash()).toBe(list[0]!.hash);
  });

  test("prunes oldest beyond MAX_SNAPSHOTS", () => {
    const s = new PolicyHistoryStore(histDir);
    // 52 distinct versions at strictly increasing timestamps
    for (let i = 0; i < 52; i++) s.record(`v${i}`, Date.UTC(2026, 0, 1, 0, 0, i));
    const list = s.list();
    expect(list.length).toBe(50);
    expect(s.read(1)).toBe("v51"); // newest kept
    // v0 and v1 pruned -> the oldest kept is v2
    expect(s.read(50)).toBe("v2");
  });
});
