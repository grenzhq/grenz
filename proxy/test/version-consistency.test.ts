/**
 * One version number, four places that state it.
 *
 * `grenz version` prints `VERSION` from src/index.ts; the three package.json
 * files are what a reader (and any future publish step) sees. They had drifted
 * to 0.5.0 / 0.1.1 / 0.2.0 / 0.2.0 — four answers to "what version is this?",
 * which is exactly the sort of thing a first release should not ship with.
 *
 * This test is the ratchet: bump them together or it fails.
 */
import { test, expect, describe } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { VERSION } from "../src/index.ts";

const REPO_ROOT = join(import.meta.dir, "..", "..");

function manifestVersion(...segments: string[]): string {
  const raw = readFileSync(join(REPO_ROOT, ...segments), "utf8");
  const parsed = JSON.parse(raw) as { version?: unknown };
  if (typeof parsed.version !== "string") {
    throw new Error(`${segments.join("/")} has no string "version"`);
  }
  return parsed.version;
}

describe("version consistency", () => {
  const MANIFESTS: readonly (readonly string[])[] = [
    ["package.json"],
    ["proxy", "package.json"],
    ["console", "package.json"],
  ];

  test("VERSION is a plain semver triple", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  for (const segments of MANIFESTS) {
    test(`${segments.join("/")} matches VERSION (${VERSION})`, () => {
      expect(manifestVersion(...segments)).toBe(VERSION);
    });
  }
});
