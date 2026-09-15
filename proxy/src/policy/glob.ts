/**
 * Deterministic glob matching for action patterns.
 *
 * Semantics (intentionally simple and total):
 *   `*`  matches any run of characters, including an empty run and `:`.
 *   `?`  matches exactly one character.
 *   every other character matches itself literally.
 *
 * Patterns are compiled to anchored `RegExp` once, at policy-compile time, so
 * request-path evaluation stays allocation-light and fully deterministic.
 */

const REGEX_SPECIAL = /[.*+?^${}()|[\]\\]/g;

/** Compile a glob pattern into an anchored regular expression. */
export function compileGlob(pattern: string, caseInsensitive = false): RegExp {
  let out = "^";
  for (const ch of pattern) {
    if (ch === "*") {
      out += ".*";
    } else if (ch === "?") {
      out += ".";
    } else {
      out += ch.replace(REGEX_SPECIAL, "\\$&");
    }
  }
  out += "$";
  // `caseInsensitive` is used ONLY for TARGET globs at protective/escalation
  // sites (grant deny/require_approval, tripwire, response cap, per-agent
  // approval overlay), so a mis-cased request can't dodge a scoped guard. Action
  // globs and allow-list targets keep the default (case-sensitive).
  return new RegExp(out, caseInsensitive ? "i" : undefined);
}

/** Test a value against a single glob pattern (compiles on each call). */
export function globMatch(pattern: string, value: string): boolean {
  return compileGlob(pattern).test(value);
}
