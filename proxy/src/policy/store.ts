/**
 * Holds the live policy set the proxy selects from per request: a shared
 * default policy, the declared-name allow-list + raw profile ENTRIES that are
 * the source of truth for per-agent profiles, and a `closed` override slot
 * for the stale-closed (fail-closed) state.
 *
 * `policyFor` is the decision-path read: closed (if set) beats everything,
 * including a profile-bearing agent's own live profile — so staleness can
 * never be bypassed by having a profile. `current`/`defaultPolicy` stay
 * read-only conveniences for non-decision callers (console display, legacy
 * reads) that only ever care about the shared default.
 *
 * Profiles are DERIVED, not stored directly: every reload re-merges the raw
 * `entries` over the (possibly new) default via `mergeProfilesOverDefault`,
 * so a change to the default is reflected in every profile too. The merge is
 * all-or-nothing and synchronous — a bad or undeclared entry fails the whole
 * reload rather than landing a partial profile map. `reload()` recompiles and
 * swaps the default the same way it always has: a successful recompile also
 * reopens (clears `closed`) and re-derives `profiles`; a rejected one leaves
 * the live default, the entries, AND the profiles untouched (fail closed —
 * keep-current, never fail-open). The file watcher and the CLI's reload
 * commands call this. The constructor performs the same merge and throws on
 * a bad/undeclared entry, so a store can never come up with an invalid
 * profile set (fail-closed startup).
 */
import { compilePolicyYaml, type CompiledPolicy } from "./compile.ts";
import { mergeProfilesOverDefault } from "./merge.ts";
import type { ProfileEntry } from "./profile-entry.ts";

export type ReloadOutcome =
  | { readonly ok: true; readonly grants: number; readonly previousGrants: number }
  // `code`/`name` are the log-safe pair for a PROFILE merge failure (F11): a
  // caller logs those, never the YAML-quoting `error`. Undefined on a
  // default-policy compile failure (no single profile to name).
  | { readonly ok: false; readonly error: string; readonly code?: string; readonly name?: string };

export class PolicyStore {
  private def: CompiledPolicy;
  private entries: readonly ProfileEntry[];
  private profiles: ReadonlyMap<string, CompiledPolicy>;
  private readonly declaredNames: ReadonlySet<string>;
  /** When set, deny-all is in force (staleness). Consulted FIRST by policyFor, so
   *  NO agent — including a profile-bearing one — sails through while closed. */
  private closed: CompiledPolicy | null = null;

  constructor(
    def: CompiledPolicy,
    declaredNames: ReadonlySet<string> = new Set(),
    entries: readonly ProfileEntry[] = [],
  ) {
    const merged = mergeProfilesOverDefault(def, entries, declaredNames);
    if (!merged.ok) throw new Error(`policy profile "${merged.name}": ${merged.error}`);
    this.def = def;
    this.declaredNames = declaredNames;
    this.entries = entries;
    this.profiles = merged.profiles;
  }

  /** The shared default policy (agents with no profile, and the console display). */
  get defaultPolicy(): CompiledPolicy {
    return this.def;
  }

  /** @deprecated alias for {@link defaultPolicy}; keeps non-decision reads stable. */
  get current(): CompiledPolicy {
    return this.def;
  }

  get profileNames(): readonly string[] {
    return [...this.profiles.keys()];
  }

  /** True while the stale-closed deny-all is in force (every selection is denied
   *  deny-all until a successful reload reopens). For operator-facing display —
   *  the decision path reads `closed` directly via {@link policyFor}, never this. */
  get isClosed(): boolean {
    return this.closed !== null;
  }

  /**
   * Select the policy for a resolved profile name.
   *   closed (stale) → deny-all — OVERRIDES the profile, so no agent escapes
   *   undefined      → default   — the agent has no profile
   *   known name     → that merged profile
   *   unknown        → null      — caller denies agent_policy_unresolved
   */
  policyFor(profile: string | undefined): CompiledPolicy | null {
    if (this.closed !== null) return this.closed;
    if (profile === undefined) return this.def;
    return this.profiles.get(profile) ?? null;
  }

  /** Swap the default and re-derive `profiles` over it, then REOPEN (clear
   *  closed). `profiles` undefined keeps the current entries (re-derives them
   *  over the new default); an array replaces the entries (`[]` clears them).
   *  A rejected recompile or merge leaves the live default, entries, AND
   *  profiles untouched — and does not reopen (fail closed, keep-current). */
  reload(defaultYaml: string, profiles?: readonly ProfileEntry[]): ReloadOutcome {
    const def = compilePolicyYaml(defaultYaml);
    if (!def.ok) {
      return { ok: false, error: def.error }; // default-compile failure: no code/name
    }
    const nextEntries = profiles ?? this.entries;
    const merged = mergeProfilesOverDefault(def.policy, nextEntries, this.declaredNames);
    if (!merged.ok) {
      // Carry the log-safe pair up so refresh/watch can emit the code + name
      // instead of the YAML-bearing `error` (F11).
      return { ok: false, error: merged.error, code: merged.code, name: merged.name };
    }
    const previousGrants = this.def.grants.size;
    this.def = def.policy;
    this.entries = nextEntries;
    this.profiles = merged.profiles;
    this.closed = null;
    return { ok: true, grants: def.policy.grants.size, previousGrants };
  }

  /** Enter the stale-closed state: deny-all overrides every selection until a
   *  later successful reload reopens. Idempotent. */
  closeAll(denyAll: CompiledPolicy): void {
    this.closed = denyAll;
  }
}
