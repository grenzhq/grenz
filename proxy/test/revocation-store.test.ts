import { test, expect, describe, afterEach } from "bun:test";
import { rmSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FleetRevocationStore, FleetRevocationError } from "../src/revocation/store.ts";

let p = "";
function path(): string {
  p = join(tmpdir(), `fleet-rev-${Math.floor(performance.now() * 1000)}.json`);
  return p;
}
afterEach(() => {
  if (p && existsSync(p)) rmSync(p);
});

describe("FleetRevocationStore", () => {
  test("absent file -> empty, floor 0", () => {
    const s = new FleetRevocationStore(path());
    expect(s.floor()).toBe(0);
    expect(s.count()).toBe(0);
    expect(s.has("a")).toBe(false);
    expect(s.expiresAt()).toBeNull();
  });

  test("replace swaps membership and persists across instances", () => {
    const fp = path();
    const s = new FleetRevocationStore(fp);
    s.replace(["b", "a"], 7, 1784500000, 1000);
    expect(s.has("a")).toBe(true);
    expect(s.has("b")).toBe(true);
    expect(s.has("c")).toBe(false);
    expect(s.version()).toBe(7);
    expect(s.floor()).toBe(7);
    expect(s.expiresAt()).toBe(1784500000);
    expect(s.list()).toEqual(["a", "b"]);
    // A restart during a plane outage keeps enforcing the cached set.
    const reloaded = new FleetRevocationStore(fp);
    expect(reloaded.has("a")).toBe(true);
    expect(reloaded.floor()).toBe(7);
    expect(reloaded.expiresAt()).toBe(1784500000);
  });

  test("replace to an empty set at a higher version un-revokes and advances the floor", () => {
    const s = new FleetRevocationStore(path());
    s.replace(["a"], 5, null, 1000);
    s.replace([], 6, null, 2000);
    expect(s.has("a")).toBe(false);
    expect(s.count()).toBe(0);
    expect(s.floor()).toBe(6);
  });

  test("corrupt file throws (fail-closed)", () => {
    const fp = path();
    writeFileSync(fp, "{ not json");
    expect(() => new FleetRevocationStore(fp)).toThrow(FleetRevocationError);
  });

  test("malformed shape throws (fail-closed)", () => {
    const fp = path();
    writeFileSync(fp, JSON.stringify({ version: "seven", revokedAgents: [] }));
    expect(() => new FleetRevocationStore(fp)).toThrow(FleetRevocationError);
  });
});
