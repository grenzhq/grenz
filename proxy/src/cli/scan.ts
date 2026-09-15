/**
 * `grenz scan [path…]` — find plaintext credentials in agent config files that
 * an infostealer would harvest today, and funnel them into the vault.
 *
 * Read-only and offline: it reads config surfaces, reports only detector names
 * and counts (the secret value never reaches stdout, a log, or the network),
 * and exits non-zero if anything is found — so it drops into CI or a pre-commit
 * hook as a "no plaintext credentials" guard. Extra paths given as arguments are
 * checked in addition to the default surfaces.
 */
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { candidatePaths } from "../scan/surfaces.ts";
import { scanFiles, renderReport, scanExitCode, type ScanInput } from "../scan/scan.ts";
import type { ParsedArgs } from "./args.ts";

export async function runScan(args: ParsedArgs): Promise<number> {
  const candidates = [...candidatePaths(process.cwd(), homedir()), ...args.positionals];

  const files: ScanInput[] = [];
  for (const path of [...new Set(candidates)]) {
    const text = await readText(path);
    if (text !== null) files.push({ path, text });
  }

  const results = scanFiles(files);
  process.stdout.write(renderReport(results, files.length));
  return scanExitCode(results);
}

/** Read a file as UTF-8, or null if it's missing, a directory, or unreadable. */
async function readText(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}
