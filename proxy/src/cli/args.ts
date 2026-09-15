/** Minimal, dependency-free argv parser for the `grenz` CLI. */

/**
 * Flags that never take a value. `version` is deliberately NOT here: bare
 * `--version` still parses as `true` (the generic rule below), while
 * `policy sign --version 7` correctly takes 7 as its value instead of leaving
 * it to fall through as a positional and trip the global version query.
 */
const BOOLEAN_FLAGS = new Set(["force", "help", "shadow", "watch", "yes", "clear-profiles", "force-version", "telemetry"]);

export interface ParsedArgs {
  readonly positionals: string[];
  readonly flags: Map<string, string | boolean>;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (token.startsWith("--")) {
      const body = token.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        flags.set(body.slice(0, eq), body.slice(eq + 1));
        continue;
      }
      if (BOOLEAN_FLAGS.has(body)) {
        flags.set(body, true);
        continue;
      }
      const next = argv[i + 1];
      // A bare "-" (the `--bundle -`/stdin convention) is a legitimate flag
      // value, not another flag — only reject tokens that start with "-" AND
      // are longer than it (i.e. look like an actual flag, e.g. "--url").
      if (next !== undefined && (next === "-" || !next.startsWith("-"))) {
        flags.set(body, next);
        i++;
      } else {
        flags.set(body, true);
      }
    } else {
      positionals.push(token);
    }
  }

  return { positionals, flags };
}

export function flagString(args: ParsedArgs, name: string): string | undefined {
  const value = args.flags.get(name);
  return typeof value === "string" ? value : undefined;
}

export function flagBool(args: ParsedArgs, name: string): boolean {
  return args.flags.get(name) === true;
}

/** The Grenz home directory from `--home`, or undefined (caller falls back). */
export function homeFlag(args: ParsedArgs): string | undefined {
  return flagString(args, "home");
}
