/**
 * Pure classification of an agent token's expiry, for operator-facing surfaces
 * (`grenz doctor`, the `grenz run` startup banner).
 *
 * This is NEVER on the decision path: `resolvePrincipal` enforces expiry with a
 * direct `expiresAtMs <= now` compare and produces no principal. This helper
 * only decides how to *tell the operator* about a token's lifecycle.
 */
const WEEK_MS = 7 * 86_400_000;

/**
 * - `"none"`   — no expiry configured (never expires).
 * - `"expired"`— past expiry (boundary `expiresAtMs === now` counts as expired,
 *   matching resolve's `<= now`).
 * - `"soon"`   — expires within `soonMs` (default 7 days), inclusive.
 * - `"ok"`     — expires, but further out than `soonMs`.
 */
export function expiryStatus(
  expiresAtMs: number | null,
  now: number,
  soonMs: number = WEEK_MS,
): "none" | "expired" | "soon" | "ok" {
  if (expiresAtMs === null) return "none";
  if (expiresAtMs <= now) return "expired";
  return expiresAtMs - now <= soonMs ? "soon" : "ok";
}
