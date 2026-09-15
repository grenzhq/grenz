/**
 * The signed-revocation refresh step, extracted from run.ts so the
 * security-critical ordering is unit-testable. Fail-static in the SAFE
 * direction for revocation: any failure keeps the cached set enforced. Never
 * un-revokes on a failed pull; never adopts an unverified or older set.
 *
 * LOAD-time only (startup + this background loop). Nothing here is reachable
 * from the request path.
 */
import type { FleetRevocationStore } from "./store.ts";
import type { RevocationFetchResult } from "./source.ts";
import type { RevocationDistributionState } from "./types.ts";

export interface RevocationRefreshDeps {
  readonly fetchSet: (minVersion: number) => Promise<RevocationFetchResult>;
  readonly store: Pick<FleetRevocationStore, "floor" | "replace">;
  /** Mutated in place on success — the gate (staleClosed), banner, and /metrics
   *  read it by reference. */
  readonly state: RevocationDistributionState;
  readonly now: () => number;
  readonly emit: (line: string) => void;
}

export type RevocationRefreshOutcome =
  | { readonly ok: true; readonly version: number; readonly count: number; readonly unchanged: boolean }
  | { readonly ok: false; readonly reason: string };

export async function refreshRevocationsOnce(deps: RevocationRefreshDeps): Promise<RevocationRefreshOutcome> {
  const res = await deps.fetchSet(deps.store.floor());
  if (!res.ok) {
    deps.emit(`[revocation] refresh REJECTED: ${res.error} — keeping the cached set`);
    return { ok: false, reason: res.error };
  }

  const now = deps.now();
  if (!res.unchanged) {
    // Swap + persist FIRST. A persist failure leaves the last-good set enforced;
    // do NOT advance state, so the liveness clock reflects the last set actually
    // in force.
    try {
      deps.store.replace(res.revokedAgents, res.version, res.expiresAt, now);
    } catch (err) {
      deps.emit(
        `[revocation] refresh REJECTED: could not persist adopted set ` +
          `(${err instanceof Error ? err.message : String(err)}) — keeping the cached set`,
      );
      return { ok: false, reason: "persist_failed" };
    }
    // Mirror the newly-adopted (and now persisted) set for the gate and /metrics.
    deps.state.count = res.revokedAgents.length;
    deps.state.expiresAt = res.expiresAt;
  }
  // On an UNCHANGED re-serve, count/expiresAt already reflect the persisted set
  // (from adoption or the startup seed) — do NOT overwrite them with the fetched
  // document's values, which were never persisted. If the org ever double-signed
  // a version with a different expiry, whoever serves the endpoint must not be
  // able to move this proxy's staleness clock or gauge away from what it enforces.
  deps.state.version = res.version;
  deps.state.lastVerifiedPullAt = now;

  if (!res.unchanged) {
    deps.emit(`[revocation] adopted fleet set v${res.version} (${res.revokedAgents.length} cut off fleet-wide)`);
  }
  return { ok: true, version: res.version, count: res.revokedAgents.length, unchanged: res.unchanged };
}

/**
 * Stale when the last verified pull is older than the bound (pull-liveness) OR
 * the signed envelope's expiry has elapsed. Expiry is evaluated regardless of
 * maxAgeSeconds — an expired envelope is stale even with no configured age
 * bound. Both feed one on_revocation_stale switch.
 */
export function isRevocationStale(
  state: RevocationDistributionState,
  maxAgeSeconds: number | undefined,
  nowMs: number,
): boolean {
  const byAge = maxAgeSeconds !== undefined && nowMs - state.lastVerifiedPullAt > maxAgeSeconds * 1000;
  const byExpiry = state.expiresAt !== null && nowMs > state.expiresAt * 1000;
  return byAge || byExpiry;
}
