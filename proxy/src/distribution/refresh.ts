/**
 * The signed-policy refresh step: pull, verify, recompile, swap. Extracted from
 * run.ts so the security-critical ordering is unit-testable.
 *
 * Every accepted policy enters through the SAME `PolicyStore.reload()` atomic
 * swap that `--watch` uses, so lint/canary/tripwire behavior applies uniformly.
 * Any failure — unreachable plane, bad signature, rolled-back version, policy
 * that will not compile — leaves the live policy in force. Never fail-open,
 * never adopt an unverified or older policy.
 *
 * This runs at LOAD time only (startup + this background loop). Nothing here is
 * reachable from the request path.
 */
import type { PolicyStore, ReloadOutcome } from "../policy/store.ts";
import type { SignedFetchResult } from "../policy/source.ts";
import type { PolicyDistributionState } from "./types.ts";

export interface RefreshDeps {
  /** Pulls + verifies a bundle, given the anti-rollback floor to enforce. */
  readonly fetchBundle: (minVersion: number) => Promise<SignedFetchResult>;
  readonly policyStore: Pick<PolicyStore, "reload">;
  readonly versionStore: { floor(): number; accept(version: number, now: number): void };
  /** Mutated in place on success — the banner and /metrics read it by reference. */
  readonly state: PolicyDistributionState;
  readonly now: () => number;
  readonly emit: (line: string) => void;
  /** Called after a successful swap (policy history capture, memory clear). */
  readonly onAdopted?: (policyYaml: string, now: number) => void;
}

export type RefreshOutcome =
  | {
      readonly ok: true;
      readonly version: number;
      readonly digest: string;
      readonly grants: number;
      /** The plane re-served the version already in force (steady state). */
      readonly unchanged: boolean;
    }
  | { readonly ok: false; readonly reason: string };

export async function refreshOnce(deps: RefreshDeps): Promise<RefreshOutcome> {
  const res = await deps.fetchBundle(deps.versionStore.floor());
  if (!res.ok) {
    deps.emit(`[policy] refresh REJECTED: ${res.error} — keeping current`);
    return { ok: false, reason: res.error };
  }

  // Recompile through the same choke point --watch uses. Absent `profiles`
  // (null) is treated as CLEAR in signed mode -- fail-closed: a profile that
  // the plane no longer sends must stop resolving, not silently keep serving
  // whatever it last was.
  const outcome: ReloadOutcome = deps.policyStore.reload(res.policyYaml, res.profiles ?? []);
  if (!outcome.ok) {
    // Authentic but unusable. Do NOT advance the floor: nothing was adopted, and
    // burning the version would block a legitimate re-publish of it. The LOG line
    // carries a fixed reason CODE (plus the profile name), NEVER `outcome.error`:
    // a profile compile message quotes the profile's own YAML (schedule times,
    // regex, tool names) — F11 keeps that off the log path. The full detail is
    // still returned via `reason` for callers that want it.
    if (outcome.code !== undefined) {
      deps.emit(`[policy] refresh REJECTED: profile "${outcome.name}": ${outcome.code} — keeping current`);
    } else {
      deps.emit(`[policy] refresh REJECTED: default policy does not compile — keeping current`);
    }
    return { ok: false, reason: outcome.error };
  }

  // State first, so an adoption that already happened is never un-recorded by a
  // failure in the persist below. Capture whether the digest actually changed
  // BEFORE overwriting it -- an unchanged-version pull whose bundle content
  // changed (F4) still needs to clear approval memory below.
  const now = deps.now();
  const digestChanged = res.digest !== deps.state.digest;
  deps.state.version = res.version;
  deps.state.digest = res.digest;
  deps.state.lastVerifiedPullAt = now;

  if (res.unchanged) {
    // The plane re-served the version already in force: the normal steady state
    // between policy changes. The reload above was a no-op recompile (and heals
    // a proxy that had been swapped to deny-all for staleness), so advance the
    // liveness clock but do not re-record history or re-clear approval memory
    // -- UNLESS the digest actually changed at this same version, in which
    // case the content did change and memory must still be cleared.
    if (digestChanged) deps.onAdopted?.(res.policyYaml, now);
    return { ok: true, version: res.version, digest: res.digest, grants: outcome.grants, unchanged: true };
  }

  deps.onAdopted?.(res.policyYaml, now);
  deps.emit(
    `[policy] adopted signed v${res.version} (${res.digest}, ${outcome.grants} grants, was ${outcome.previousGrants})`,
  );

  // Persist the anti-rollback floor last, in its own failure domain: a write
  // error must not discard an adoption that has already taken effect.
  try {
    deps.versionStore.accept(res.version, now);
  } catch (err) {
    deps.emit(
      `[policy] WARNING: adopted v${res.version} but could not persist the anti-rollback floor ` +
        `(${err instanceof Error ? err.message : String(err)}) — a restart may re-accept an older version`,
    );
  }
  return { ok: true, version: res.version, digest: res.digest, grants: outcome.grants, unchanged: false };
}

/** True when the last verified pull is older than the configured bound. */
export function isStale(
  state: PolicyDistributionState,
  maxAgeSeconds: number | undefined,
  now: number,
): boolean {
  if (maxAgeSeconds === undefined) return false;
  return now - state.lastVerifiedPullAt > maxAgeSeconds * 1000;
}

/**
 * A policy with zero grants: deny-by-default means it denies everything. Used
 * only by `on_stale: fail_closed`, where the proxy would rather refuse than keep
 * enforcing rules it can no longer confirm are current. Identifiers go through
 * JSON.stringify (JSON is a subset of YAML 1.2) so a hostile agent id cannot
 * inject structure into the synthesized document.
 */
export function denyAllYaml(agent: string, onBehalfOf: string): string {
  return `agent: ${JSON.stringify(agent)}\non_behalf_of: ${JSON.stringify(onBehalfOf)}\ngrants: []\n`;
}

/* -------------------------------------------------------------------------
   The unsigned refresh step.

   Unsigned distribution had no refresh loop at all: `refresh_seconds` and
   `on_stale` were accepted by the schema, written into grenz.yaml by
   `grenz connect`, and then read by nothing. A proxy whose first pull was
   rejected served the local policy.yaml indefinitely while its config claimed
   `on_stale: fail_closed` — enforcement the config promised and the code could
   not deliver, which is the exact failure the schema's own superRefine exists
   to prevent.

   Same contract as the signed step above: every accepted policy enters through
   `PolicyStore.reload()`, and any failure leaves the live policy in force.
   There is no version here and so no anti-rollback floor — unsigned transport
   cannot offer one, which is what the "pin a key" warning is about. What it CAN
   offer is a liveness clock, and that is what staleness acts on.
   ---------------------------------------------------------------------- */

export interface UnsignedRefreshDeps {
  readonly fetchPolicy: () => Promise<{ ok: true; policyYaml: string } | { ok: false; error: string }>;
  readonly policyStore: Pick<PolicyStore, "reload">;
  /** Mutated in place on success — the banner, the gate, and /metrics read it. */
  readonly state: PolicyDistributionState;
  readonly now: () => number;
  readonly emit: (line: string) => void;
  /** Injected so this stays pure-ish and testable without crypto in the test. */
  readonly digestOf: (policyYaml: string) => Promise<string>;
  readonly onAdopted?: (policyYaml: string, now: number) => void;
}

export type UnsignedRefreshOutcome =
  | { readonly ok: true; readonly grants: number; readonly unchanged: boolean }
  | { readonly ok: false; readonly reason: string };

export async function refreshUnsignedOnce(deps: UnsignedRefreshDeps): Promise<UnsignedRefreshOutcome> {
  const res = await deps.fetchPolicy();
  if (!res.ok) {
    deps.emit(`[policy] refresh REJECTED: ${res.error} — keeping current`);
    return { ok: false, reason: res.error };
  }

  // No `profiles` argument: profiles are a signed-bundle concept. Passing []
  // here would CLEAR any locally declared profiles on every refresh, so the
  // unsigned path deliberately leaves them alone.
  const outcome: ReloadOutcome = deps.policyStore.reload(res.policyYaml);
  if (!outcome.ok) {
    // Never `outcome.error` on the log path — a compile message quotes the
    // policy's own YAML. The detail still goes back to the caller via `reason`.
    deps.emit(`[policy] refresh REJECTED: pulled policy does not compile — keeping current`);
    return { ok: false, reason: outcome.error };
  }

  // The liveness clock advances only on a pull that actually compiled and
  // swapped. Advancing it on a fetch that failed to compile would be the
  // fail-open this whole path exists to close.
  const now = deps.now();
  deps.state.lastVerifiedPullAt = now;

  // Unsigned has no version to compare, so "unchanged" is decided on the same
  // digest the signed path uses. The no-op recompile above still ran, which is
  // what heals a proxy that had been swapped to deny-all for staleness; it just
  // must not re-record history or re-clear remembered approvals.
  const digest = await deps.digestOf(res.policyYaml);
  const unchanged = digest === deps.state.digest;
  deps.state.digest = digest;
  if (unchanged) return { ok: true, grants: outcome.grants, unchanged: true };

  deps.onAdopted?.(res.policyYaml, now);
  deps.emit(`[policy] adopted unsigned policy (${outcome.grants} grants, was ${outcome.previousGrants})`);
  return { ok: true, grants: outcome.grants, unchanged: false };
}
