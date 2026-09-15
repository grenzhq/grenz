/**
 * The signed-startup adoption ordering, extracted so the security-critical rule —
 * the version floor is accepted ONLY after the bundle's profiles are validated
 * (F1) — is unit-testable. Signed mode only; profiles come from the bundle
 * (absent ⇒ [], F3), never from local files (F2, handled by the caller).
 */
import { mergeProfilesOverDefault } from "../policy/merge.ts";
import type { ProfileEntry } from "../policy/profile-entry.ts";
import type { SignedFetchResult } from "../policy/source.ts";

type OkPull = Extract<SignedFetchResult, { ok: true }>;

export function adoptSignedStartup(args: {
  signed: OkPull;
  declaredNames: ReadonlySet<string>;
  accept: (version: number, at: number) => void;
  now: () => number;
}): { ok: true; entries: readonly ProfileEntry[]; at: number } | { ok: false; error: string } {
  const entries = args.signed.profiles ?? []; // absent ⇒ clear (F3)
  const merged = mergeProfilesOverDefault(args.signed.policy, entries, args.declaredNames);
  if (!merged.ok) return { ok: false, error: `profile "${merged.name}": ${merged.code}` }; // F11: code only
  const at = args.now();
  args.accept(args.signed.version, at); // ONLY after a successful merge (F1)
  return { ok: true, entries, at };
}

/**
 * Pure selection of the profile ENTRIES a freshly-built PolicyStore starts from,
 * with the F2 fail-open-prevention in ONE place: in signed mode the entries come
 * ONLY from the bundle — the validated set on a good pull, `[]` on a failed one —
 * NEVER from `localEntries`. A plane outage/hostile response at a restart must
 * boot profile-bearing agents into deny (`agent_policy_unresolved`), not onto
 * stale/broader local files. Non-signed mode keeps the local entries.
 */
export function startupProfileEntries(args: {
  signedMode: boolean;
  signedPullOk: boolean;
  bundleEntries: readonly ProfileEntry[];
  localEntries: readonly ProfileEntry[];
}): readonly ProfileEntry[] {
  return args.signedMode ? (args.signedPullOk ? args.bundleEntries : []) : args.localEntries;
}
