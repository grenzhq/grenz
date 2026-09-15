/**
 * HTTP header values must be a byte string (Latin1). Operator-authored policy
 * text — a tripwire `note`, a deny-rule `message` surfaced as `x-grenz-hint` —
 * is UTF-8 and routinely contains an em-dash, a curly quote, an emoji, or an
 * accented word. Setting such a value on a `Response` header throws a TypeError
 * ("invalid value"), which would turn a clean 403 deny into a 500 internal_error
 * and drop the hint entirely. So fold the value to printable ASCII for the
 * header; the full UTF-8 text still travels in the JSON response body.
 *
 * Pure and total: common typographic punctuation is normalised to its ASCII
 * equivalent (so the header stays readable), and anything else outside printable
 * ASCII becomes `?`.
 */
export function headerSafe(value: string): string {
  return value
    .replace(/[‐-―−]/g, "-") // hyphen/dash variants, minus sign
    .replace(/[‘’‚‛]/g, "'") // single curly quotes
    .replace(/[“”„‟]/g, '"') // double curly quotes
    .replace(/…/g, "...") // ellipsis
    .replace(/[^\x20-\x7E]/g, "?"); // anything else non-printable-ASCII
}
