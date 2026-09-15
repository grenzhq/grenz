/**
 * Types for signed policy-bundle verification. The bundle is a control INPUT
 * (the policy artifact) — verifying it is supply-chain integrity, NOT
 * tamper-evident logging. Deny codes are fixed strings carrying no key bytes
 * or policy content.
 */
import type { ProfileEntry } from "../policy/profile-entry.ts";

export type BundleDenyCode = "bundle_malformed" | "bad_signature" | "stale_version";

export type BundleVerifyResult =
  | {
      readonly ok: true;
      readonly version: number;
      readonly policyYaml: string;
      readonly digest: string;
      /**
       * The bundle is exactly the version already accepted — the normal case
       * between policy changes. Verified and safe to adopt, but nothing new: the
       * caller should refresh its liveness clock without re-recording history.
       */
      readonly unchanged: boolean;
      readonly profiles: readonly ProfileEntry[] | null;
    }
  | { readonly ok: false; readonly code: BundleDenyCode };

/**
 * Live current-state of signed policy distribution: which version is running
 * right now, its digest, and when it was last verified. Mutable and read by
 * reference (the banner and /metrics see refresh-loop updates immediately).
 *
 * This is ONE current row, overwritten in place — deliberately not a timeline
 * of which policy was active when. Operational visibility, nothing more.
 */
export interface PolicyDistributionState {
  /** Running signed version; 0 when the policy is local or unsigned. */
  version: number;
  /** sha256 of the running policy YAML (first 12 hex chars); "" when local. */
  digest: string;
  /** ms epoch of the last successful verified pull; 0 when never pulled. */
  lastVerifiedPullAt: number;
}
