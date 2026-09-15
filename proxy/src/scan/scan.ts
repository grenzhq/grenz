/**
 * `grenz scan` core — find plaintext credentials sitting in agent config files
 * that an infostealer would harvest today, and funnel them into the vault.
 *
 * Reuses the DLP detector, so a finding reports only the detector NAME and a
 * match count — NEVER the matched secret value. The value must never reach
 * stdout, a log, or anywhere off this machine. Pure + synchronous; the CLI
 * shell (`cli/scan.ts`) does the file I/O.
 */
import { scanForSecrets, type DlpFinding } from "../dlp/scan.ts";

export interface ScanInput {
  readonly path: string;
  readonly text: string;
}

export interface FileFindings {
  readonly path: string;
  readonly findings: readonly DlpFinding[];
}

/** Scan already-read files. One entry per file that has ≥1 finding. Pure. */
export function scanFiles(files: readonly ScanInput[]): FileFindings[] {
  const out: FileFindings[] = [];
  for (const f of files) {
    const findings = scanForSecrets(f.text);
    if (findings.length > 0) out.push({ path: f.path, findings });
  }
  return out;
}

/** Total secret matches across all files. */
export function totalSecrets(results: readonly FileFindings[]): number {
  return results.reduce((n, r) => n + r.findings.reduce((m, f) => m + f.count, 0), 0);
}

/** 1 if any secret was found (CI-friendly non-zero), else 0. */
export function scanExitCode(results: readonly FileFindings[]): number {
  return results.length > 0 ? 1 : 0;
}

/**
 * The human report. NEVER contains a secret value — only detector names and
 * counts, plus how to move each secret into the vault.
 */
export function renderReport(results: readonly FileFindings[], scannedCount: number): string {
  if (results.length === 0) {
    return `grenz scan — checked ${scannedCount} file(s), found no plaintext credentials. ✓\n`;
  }
  const total = totalSecrets(results);
  const lines: string[] = [
    `grenz scan — ${total} plaintext credential(s) an infostealer would take right now,`,
    `across ${results.length} of ${scannedCount} file(s) checked:`,
    "",
  ];
  for (const r of results) {
    lines.push(`  ${r.path}`);
    for (const f of r.findings) lines.push(`    · ${f.detector} ×${f.count}`);
  }
  lines.push(
    "",
    "These sit in plaintext — off-box that's a straight credential harvest.",
    "Move each behind the vault so the file holds only a revocable token:",
    "  grenz protect                                # vault your upstream token + safe-defaults",
    '  printf %s "$SECRET" | grenz vault set <key>  # any other secret',
    "",
  );
  return lines.join("\n");
}
