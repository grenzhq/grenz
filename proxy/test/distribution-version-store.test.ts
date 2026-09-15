import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PolicyVersionStore, PolicyVersionStoreError } from "../src/distribution/version-store.ts";

describe("PolicyVersionStore", () => {
  let dir: string, path: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "grenz-pv-")); path = join(dir, "policy-version.json"); });
  afterEach(async () => rm(dir, { recursive: true, force: true }));

  test("floor is 0 when absent", () => { expect(new PolicyVersionStore(path).floor()).toBe(0); });
  test("accept advances the floor and persists across instances", () => {
    const s = new PolicyVersionStore(path);
    s.accept(7, 1000);
    expect(s.floor()).toBe(7);
    expect(new PolicyVersionStore(path).floor()).toBe(7);
  });
  test("accept never lowers the floor", () => {
    const s = new PolicyVersionStore(path);
    s.accept(7, 1000);
    s.accept(3, 2000);
    expect(s.floor()).toBe(7);
  });
  test("a corrupt file throws on load (fail-closed)", async () => {
    await writeFile(path, "{ not json");
    expect(() => new PolicyVersionStore(path)).toThrow(PolicyVersionStoreError);
  });
});
