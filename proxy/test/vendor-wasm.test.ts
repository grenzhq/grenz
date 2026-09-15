/**
 * The vendored .wasm must match vendor/wasm/checksums.txt. Lives in the test
 * suite rather than as a CI step so it runs wherever `bun test` runs, with no
 * workflow edit needed. See vendor/wasm/PROVENANCE.md.
 */
import { test, expect } from "bun:test";
import { join } from "node:path";

test("vendored wasm matches checksums.txt", () => {
  const r = Bun.spawnSync(["bun", "run", join(import.meta.dir, "..", "scripts", "verify-wasm.ts")]);
  expect(r.exitCode, new TextDecoder().decode(r.stderr)).toBe(0);
});
