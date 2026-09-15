/**
 * The ONE place the grants-only profile merge lives, shared by the local loader
 * and the store's bundle reload, so a cloud-delivered profile is as safe as a
 * local one. Reject-only, all-or-nothing, synchronous.
 */
import { compilePolicyYaml, type CompiledPolicy } from "./compile.ts";
import type { ProfileEntry } from "./profile-entry.ts";

export type ProfileMergeCode = "parse_error" | "undeclared" | "duplicate";

export type ProfileMergeResult =
  | { readonly ok: true; readonly profiles: ReadonlyMap<string, CompiledPolicy> }
  | { readonly ok: false; readonly name: string; readonly code: ProfileMergeCode; readonly error: string };

/**
 * Compile each entry's YAML and merge its grants over `def` (grants-only: every
 * protective construct is inherited from `def`). Aborts on the first of: a name
 * not in `declaredNames` (F6), a duplicate name, a compile failure — with NO
 * partial map. `error` carries full detail (CLI validator); `name`+`code` are the
 * log-safe pair (F11 — callers log the code, never the YAML-quoting `error`).
 */
export function mergeProfilesOverDefault(
  def: CompiledPolicy,
  entries: readonly ProfileEntry[],
  declaredNames: ReadonlySet<string>,
): ProfileMergeResult {
  const out = new Map<string, CompiledPolicy>();
  for (const e of entries) {
    if (!declaredNames.has(e.name)) {
      return { ok: false, name: e.name, code: "undeclared", error: `profile "${e.name}" is not declared in policy_profiles` };
    }
    if (out.has(e.name)) {
      return { ok: false, name: e.name, code: "duplicate", error: `duplicate profile "${e.name}"` };
    }
    const r = compilePolicyYaml(e.policy);
    if (!r.ok) {
      return { ok: false, name: e.name, code: "parse_error", error: `policy profile "${e.name}": ${r.error}` };
    }
    // Grants-only override: protective constructs are INHERITED from `def`, only
    // the grants (and `source`) come from the profile's OWN policy (F12). The
    // split is latent — no live reader currently consumes a merged profile's
    // `.source` on a path that matters — so this is not behavior-load-bearing today.
    out.set(e.name, { ...def, grants: r.policy.grants, source: r.policy.source });
  }
  return { ok: true, profiles: out };
}
