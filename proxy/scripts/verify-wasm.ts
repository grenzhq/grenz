#!/usr/bin/env bun
/**
 * Re-verify the vendored WebAssembly against `vendor/wasm/checksums.txt`.
 *
 * Grenz signs policy bundles; binary blobs in the repo get the same treatment.
 * Run in CI on every push — a `.wasm` that changed without its checksum and
 * PROVENANCE.md entry changing is a supply-chain event, not a diff to skim.
 *
 *   bun run verify:wasm           check (exit 1 on mismatch)
 *   bun run verify:wasm --write   regenerate checksums.txt after a deliberate update
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const DIR = join(import.meta.dir, "..", "vendor", "wasm");
const CHECKSUMS = join(DIR, "checksums.txt");

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** `<sha256>  <name>` per line — the shasum(1) format, so it is checkable by hand. */
function parseChecksums(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split("\n")) {
    const m = /^([0-9a-f]{64})\s+(.+)$/.exec(line.trim());
    if (m) out.set(m[2]!, m[1]!);
  }
  return out;
}

const onDisk = readdirSync(DIR)
  .filter((f) => f.endsWith(".wasm"))
  .sort();

if (process.argv.includes("--write")) {
  const lines = onDisk.map((f) => `${sha256(join(DIR, f))}  ${f}`);
  writeFileSync(CHECKSUMS, lines.join("\n") + "\n");
  process.stdout.write(`wrote ${onDisk.length} checksum(s) to vendor/wasm/checksums.txt\n`);
  for (const l of lines) process.stdout.write(`  ${l}\n`);
  process.exit(0);
}

let expected: Map<string, string>;
try {
  expected = parseChecksums(readFileSync(CHECKSUMS, "utf8"));
} catch {
  process.stderr.write("verify-wasm: vendor/wasm/checksums.txt is missing\n");
  process.exit(1);
}

const problems: string[] = [];

// An UNLISTED .wasm is as much of a finding as a changed one — that is how an
// extra blob would arrive.
for (const file of onDisk) {
  const want = expected.get(file);
  if (want === undefined) {
    problems.push(`${file}: present on disk but not listed in checksums.txt`);
    continue;
  }
  const got = sha256(join(DIR, file));
  if (got !== want) {
    problems.push(`${file}: SHA-256 mismatch\n    expected ${want}\n    actual   ${got}`);
  }
}
for (const file of expected.keys()) {
  if (!onDisk.includes(file)) problems.push(`${file}: listed in checksums.txt but missing on disk`);
}

if (problems.length > 0) {
  process.stderr.write("verify-wasm: FAILED\n");
  for (const p of problems) process.stderr.write(`  ${p}\n`);
  process.stderr.write(
    "\nIf this change was deliberate, follow the update procedure in " +
      "vendor/wasm/PROVENANCE.md and re-run with --write.\n",
  );
  process.exit(1);
}

process.stdout.write(`verify-wasm: ok — ${onDisk.length} file(s) match checksums.txt\n`);
