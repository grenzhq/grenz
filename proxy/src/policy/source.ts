/**
 * Remote policy distribution (invariant 3: the cloud plane DISTRIBUTES policy;
 * it never decides). The proxy pulls a policy YAML from the control plane and
 * compiles it locally — the engine stays embedded, so there is no network hop on
 * the decision path. The caller falls back to the local policy.yaml if the pull
 * fails, so a cloud outage never takes the proxy down.
 */
import { compilePolicyYaml, type CompiledPolicy } from "./compile.ts";
import { verifyPolicyBundle } from "../distribution/verify.ts";
import type { ProfileEntry } from "./profile-entry.ts";

const FETCH_TIMEOUT_MS = 5000;

export type PolicyFetchResult =
  /** `policyYaml` is the source bytes, returned alongside the compiled policy so
   *  the refresh loop can push it through the same `PolicyStore.reload()` atomic
   *  swap that `--watch` and the signed path use. */
  | { readonly ok: true; readonly policy: CompiledPolicy; readonly policyYaml: string }
  | { readonly ok: false; readonly error: string };

export async function fetchRemotePolicy(url: string, orgToken: string): Promise<PolicyFetchResult> {
  let text: string;
  try {
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${orgToken}` },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `policy source returned ${res.status}` };
    text = await res.text();
  } catch {
    return { ok: false, error: "policy source unreachable" };
  }
  // Compiling here means a malformed remote policy fails closed to the caller's
  // local fallback rather than being served.
  const compiled = compilePolicyYaml(text);
  if (!compiled.ok) return { ok: false, error: compiled.error };
  return { ok: true, policy: compiled.policy, policyYaml: text };
}

/**
 * Signed variant: the plane serves an Ed25519-signed, versioned bundle that the
 * proxy verifies against locally pinned public keys before compiling. The plane
 * never holds the signing key, so a compromised plane can serve only what the
 * org already signed — and never an older version replayed to weaken the fleet
 * (anti-rollback via `minVersion`). Verification happens here, at LOAD time;
 * nothing on the request path ever touches a signature.
 *
 * `policyYaml` is returned alongside the compiled policy so the refresh loop can
 * push it through the same `PolicyStore.reload()` atomic swap that `--watch` uses.
 */
export type SignedFetchResult =
  | {
      readonly ok: true;
      readonly policy: CompiledPolicy;
      readonly policyYaml: string;
      readonly version: number;
      readonly digest: string;
      /** The plane served the version already in force — verified, but not new. */
      readonly unchanged: boolean;
      readonly profiles: readonly ProfileEntry[] | null;
    }
  | { readonly ok: false; readonly error: string };

/** Cap the fetched bundle body BEFORE parse/verify — an unauthenticated body must
 *  not force an unbounded parse. */
export const MAX_SIGNED_BODY_BYTES = 4 * 1024 * 1024;

export async function fetchSignedPolicy(
  url: string,
  orgToken: string,
  pinnedKeys: string[],
  minVersion: number,
): Promise<SignedFetchResult> {
  let text: string;
  try {
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${orgToken}` },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false, error: `policy source returned ${res.status}` };
    text = await res.text();
  } catch {
    return { ok: false, error: "policy source unreachable" };
  }
  if (text.length > MAX_SIGNED_BODY_BYTES) {
    return { ok: false, error: "signed policy rejected: bundle too large" };
  }
  const v = await verifyPolicyBundle(text, pinnedKeys, minVersion);
  if (!v.ok) {
    const why =
      v.code === "stale_version"
        ? "stale (anti-rollback)"
        : v.code === "bad_signature"
          ? "signature invalid"
          : "malformed bundle";
    return { ok: false, error: `signed policy rejected: ${why}` };
  }
  const compiled = compilePolicyYaml(v.policyYaml);
  if (!compiled.ok) return { ok: false, error: compiled.error };
  return {
    ok: true,
    policy: compiled.policy,
    policyYaml: v.policyYaml,
    version: v.version,
    digest: v.digest,
    unchanged: v.unchanged,
    profiles: v.profiles,
  };
}
