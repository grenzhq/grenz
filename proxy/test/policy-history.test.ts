import { test, expect, describe } from "bun:test";
import {
  shortHash,
  compactStamp,
  snapshotFilename,
  parseSnapshotName,
  sortSnapshotsNewestFirst,
  snapshotsToPrune,
} from "../src/policy/history.ts";

describe("shortHash", () => {
  test("deterministic, 8 lowercase hex chars", () => {
    const h = shortHash("hello");
    expect(h).toMatch(/^[0-9a-f]{8}$/);
    expect(shortHash("hello")).toBe(h);
  });
  test("different content differs", () => {
    expect(shortHash("a")).not.toBe(shortHash("b"));
  });
});

describe("compactStamp", () => {
  test("compact UTC form", () => {
    // 2026-07-15T14:02:00.000Z
    const ms = Date.UTC(2026, 6, 15, 14, 2, 0);
    expect(compactStamp(ms)).toBe("20260715T140200Z");
  });
});

describe("snapshotFilename / parseSnapshotName", () => {
  test("round-trips", () => {
    const ms = Date.UTC(2026, 6, 15, 14, 2, 0);
    const name = snapshotFilename(ms, "policy text");
    expect(name).toBe(`20260715T140200Z-${shortHash("policy text")}.yaml`);
    const meta = parseSnapshotName(name);
    expect(meta).not.toBeNull();
    expect(meta!.stamp).toBe("20260715T140200Z");
    expect(meta!.hash).toBe(shortHash("policy text"));
    expect(meta!.name).toBe(name);
  });
  test("rejects non-matching names", () => {
    expect(parseSnapshotName("policy.yaml")).toBeNull();
    expect(parseSnapshotName("nope.txt")).toBeNull();
    expect(parseSnapshotName("20260715T140200Z.yaml")).toBeNull();
  });
});

describe("sortSnapshotsNewestFirst", () => {
  test("newest stamp first, ignores unparseable", () => {
    const names = [
      "20260714T090000Z-aaaaaaaa.yaml",
      "20260715T140200Z-bbbbbbbb.yaml",
      "garbage.yaml",
      "20260715T112000Z-cccccccc.yaml",
    ];
    const sorted = sortSnapshotsNewestFirst(names);
    expect(sorted.map((s) => s.stamp)).toEqual([
      "20260715T140200Z",
      "20260715T112000Z",
      "20260714T090000Z",
    ]);
  });
});

describe("snapshotsToPrune", () => {
  const meta = (stamp: string) => ({ name: `${stamp}-abcabcab.yaml`, stamp, hash: "abcabcab" });
  test("nothing to prune at or under the cap", () => {
    const list = [meta("20260715T140200Z"), meta("20260715T112000Z")];
    expect(snapshotsToPrune(list, 2)).toEqual([]);
    expect(snapshotsToPrune(list, 5)).toEqual([]);
  });
  test("prunes the oldest over the cap", () => {
    const list = [
      meta("20260715T140200Z"),
      meta("20260715T112000Z"),
      meta("20260714T090000Z"),
    ];
    expect(snapshotsToPrune(list, 2)).toEqual(["20260714T090000Z-abcabcab.yaml"]);
  });
});
