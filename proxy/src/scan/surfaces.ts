/**
 * The config surfaces `grenz scan` checks by default — the files agent tooling
 * commonly leaves long-lived credentials in. A curated list (deny-by-default
 * spirit: we never walk all of $HOME), plus any paths the user passes on the
 * command line.
 */
import { join } from "node:path";

/** Filenames checked in the current working directory. */
export const CWD_SURFACES: readonly string[] = [
  ".env",
  ".env.local",
  ".env.development",
  ".env.production",
  "mcp.json",
  ".mcp.json",
  ".claude.json",
  "claude_desktop_config.json",
];

/** Paths (relative to $HOME) checked as well. */
export const HOME_SURFACES: readonly string[] = [
  ".claude.json",
  ".claude/settings.json",
  ".config/claude/claude_desktop_config.json",
  "Library/Application Support/Claude/claude_desktop_config.json",
];

/** Absolute candidate paths to check, given a working dir and a home dir. Pure. */
export function candidatePaths(cwd: string, home: string): string[] {
  const paths = [
    ...CWD_SURFACES.map((f) => join(cwd, f)),
    ...HOME_SURFACES.map((f) => join(home, f)),
  ];
  return [...new Set(paths)];
}
