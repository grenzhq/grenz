import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { GrantStore, GrantError } from "../src/grant/store.ts";

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-grant-"));
  path = join(dir, "grants.json");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const mint = (
  s: GrantStore,
  over?: Partial<{ agentId: string; actions: string[]; ttlMs: number; reason: string; now: number }>,
) =>
  s.mint({
    agentId: over?.agentId ?? "claude-code",
    actions: over?.actions ?? ["pr:merge"],
    ttlMs: over?.ttlMs ?? 60_000,
    reason: over?.reason ?? "",
    now: over?.now ?? 1000,
  });

describe("GrantStore", () => {
  test("mint returns a grant with the requested scope", () => {
    const s = new GrantStore(path);
    const g = mint(s, { actions: ["pr:merge", "repo:delete"], reason: "hotfix" });
    expect(g.agentId).toBe("claude-code");
    expect(g.actions).toEqual(["pr:merge", "repo:delete"]);
    expect(g.reason).toBe("hotfix");
  });

  test("list excludes expired grants and is newest-first", () => {
    const s = new GrantStore(path);
    mint(s, { actions: ["a"], now: 1000, ttlMs: 60_000 });
    mint(s, { actions: ["b"], now: 2000, ttlMs: 60_000 });
    mint(s, { actions: ["c"], now: 500, ttlMs: 100 }); // expired by now=3000
    const live = s.list(3000);
    expect(live.map((g) => g.actions[0])).toEqual(["b", "a"]);
  });

  test("persists across reopen (a restart still honors live grants)", () => {
    const s = new GrantStore(path);
    mint(s, { actions: ["issue:read"], ttlMs: 60_000, now: 1000 });
    const reopened = new GrantStore(path);
    expect(reopened.list(2000).map((g) => g.actions[0])).toEqual(["issue:read"]);
  });

  test("purgeExpired drops dead records and persists", () => {
    const s = new GrantStore(path);
    mint(s, { ttlMs: 100, now: 1000 }); // expires 1100
    mint(s, { ttlMs: 60_000, now: 1000 });
    expect(s.purgeExpired(5000)).toBe(1);
    expect(new GrantStore(path).list(5000).length).toBe(1);
  });

  test("atCapacity reflects only live grants", () => {
    const s = new GrantStore(path);
    for (let i = 0; i < 3; i++) mint(s, { now: 1000, ttlMs: 100 }); // all expire by 5000
    expect(s.atCapacity(5000)).toBe(false);
  });

  test("corrupt file throws GrantError (fail closed)", () => {
    writeFileSync(path, "not json at all");
    expect(() => new GrantStore(path)).toThrow(GrantError);
  });

  test("distinct ids are minted per grant", () => {
    const s = new GrantStore(path);
    const a = mint(s);
    const b = mint(s);
    expect(a.id).not.toBe(b.id);
  });
});
