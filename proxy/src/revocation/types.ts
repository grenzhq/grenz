export type RevocationDenyCode = "set_malformed" | "bad_signature" | "stale_version";

export type RevocationVerifyResult =
  | {
      readonly ok: true;
      readonly version: number;
      /** Sorted + deduplicated. */
      readonly revokedAgents: readonly string[];
      /** Signer's freshness assertion (epoch seconds); null when none. */
      readonly expiresAt: number | null;
      /** The set is exactly the version already accepted (steady state). */
      readonly unchanged: boolean;
    }
  | { readonly ok: false; readonly code: RevocationDenyCode };

/**
 * Live fleet-revocation runtime state, mutated in place by the refresh loop and
 * read by reference by the dispatch gate (`staleClosed`), /metrics, and the
 * banner. Current-state only — never a history.
 */
export interface RevocationDistributionState {
  /** Running set version; 0 when none loaded/pulled. */
  version: number;
  /** Agents in the running set (for the gauge). */
  count: number;
  /** Signer's freshness assertion (epoch seconds); null when none. */
  expiresAt: number | null;
  /** ms epoch of the last verified pull THIS run; 0 when never pulled. */
  lastVerifiedPullAt: number;
  /** Set true by the staleness checker under on_revocation_stale=fail_closed;
   *  the gate denies ALL requests with `revocation_stale` while true. */
  staleClosed: boolean;
}
