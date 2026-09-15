import { test, expect, describe } from "bun:test";
import { refreshOnce, isStale, denyAllYaml, type RefreshDeps } from "../src/distribution/refresh.ts";
import type { PolicyDistributionState } from "../src/distribution/types.ts";
import type { SignedFetchResult } from "../src/policy/source.ts";
import { PolicyStore, type ReloadOutcome } from "../src/policy/store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { evaluate } from "../src/policy/evaluate.ts";
import type { ProfileEntry } from "../src/policy/profile-entry.ts";

const YAML_V1 = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;
const YAML_V2 = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read, repo:write]`;

/** The compiled `allow` list holds matcher objects; compare their sources. */
function allowSources(store: PolicyStore): string[] {
  return (store.current.grants.get("github")?.allow ?? []).map((a) => a.action.source);
}

function compiled(yaml: string) {
  const c = compilePolicyYaml(yaml);
  if (!c.ok) throw new Error(`fixture does not compile: ${c.error}`);
  return c.policy;
}

function harness(
  fetchBundle: (minVersion: number) => Promise<SignedFetchResult>,
  floor = 0,
  opts: { acceptThrows?: boolean; declaredNames?: ReadonlySet<string> } = {},
) {
  const state: PolicyDistributionState = { version: 0, digest: "", lastVerifiedPullAt: 0 };
  const policyStore = new PolicyStore(compiled(YAML_V1), opts.declaredNames ?? new Set(["ci"]));
  const reloadCalls: Array<{ yaml: string; profiles: readonly ProfileEntry[] | undefined }> = [];
  const realReload = policyStore.reload.bind(policyStore);
  const reloadSpy = (yaml: string, profiles?: readonly ProfileEntry[]): ReloadOutcome => {
    reloadCalls.push({ yaml, profiles });
    return realReload(yaml, profiles);
  };
  let acceptedFloor = floor;
  const lines: string[] = [];
  const seenMinVersions: number[] = [];
  const adopted: string[] = [];
  const deps: RefreshDeps = {
    fetchBundle: (min) => {
      seenMinVersions.push(min);
      return fetchBundle(min);
    },
    policyStore: { reload: reloadSpy },
    versionStore: {
      floor: () => acceptedFloor,
      accept: (v) => {
        if (opts.acceptThrows) throw new Error("ENOSPC");
        if (v > acceptedFloor) acceptedFloor = v;
      },
    },
    state,
    now: () => 5_000,
    emit: (l) => lines.push(l),
    onAdopted: (yaml) => adopted.push(yaml),
  };
  return { deps, state, policyStore, lines, seenMinVersions, adopted, reloadCalls, floorNow: () => acceptedFloor };
}

const okResult = (
  version: number,
  yaml: string,
  unchanged = false,
  profiles: readonly ProfileEntry[] | null = null,
  digest = "abc123abc123",
): SignedFetchResult => ({
  ok: true,
  policy: compiled(yaml),
  policyYaml: yaml,
  version,
  digest,
  unchanged,
  profiles,
});

describe("refreshOnce", () => {
  test("a verified newer bundle swaps the live policy and advances the floor", async () => {
    const h = harness(async () => okResult(4, YAML_V2));
    const out = await refreshOnce(h.deps);
    expect(out).toEqual({ ok: true, version: 4, digest: "abc123abc123", grants: 1, unchanged: false });
    expect(allowSources(h.policyStore)).toContain("repo:write");
    expect(h.floorNow()).toBe(4);
    expect(h.state).toEqual({ version: 4, digest: "abc123abc123", lastVerifiedPullAt: 5_000 });
  });

  test("it passes the persisted floor to the fetch (anti-rollback wiring)", async () => {
    const h = harness(async () => okResult(9, YAML_V2), 6);
    await refreshOnce(h.deps);
    expect(h.seenMinVersions).toEqual([6]);
  });

  test("a rejected bundle leaves the live policy, floor, and state untouched", async () => {
    const h = harness(async () => ({ ok: false, error: "signed policy rejected: signature invalid" }), 3);
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(false);
    expect(allowSources(h.policyStore)).not.toContain("repo:write");
    expect(h.floorNow()).toBe(3);
    expect(h.state).toEqual({ version: 0, digest: "", lastVerifiedPullAt: 0 });
    expect(h.lines.join("\n")).toContain("signature invalid");
  });

  test("an unreachable plane leaves the live policy in force (never fail-open)", async () => {
    const h = harness(async () => ({ ok: false, error: "policy source unreachable" }));
    expect((await refreshOnce(h.deps)).ok).toBe(false);
    expect(h.policyStore.current.grants.size).toBe(1);
    expect(h.state.lastVerifiedPullAt).toBe(0);
  });

  test("a verified bundle that fails to recompile does NOT advance the floor", async () => {
    // Verified authentic, but the YAML is not a valid policy: adopting nothing
    // must also mean burning nothing -- otherwise the floor would block the
    // legitimate re-publish of that version.
    const h = harness(async () => ({
      ok: true,
      policy: compiled(YAML_V1),
      policyYaml: "this: is not: valid: policy",
      version: 8,
      digest: "deadbeefdead",
      unchanged: false,
      profiles: null,
    }));
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(false);
    expect(h.floorNow()).toBe(0);
    expect(h.state.version).toBe(0);
  });
});

describe("refreshOnce steady state (the plane re-serves the version already in force)", () => {
  test("an unchanged bundle advances the liveness clock", async () => {
    // The bug this guards: minVersion is the last-ACCEPTED version, so between
    // policy changes the plane always serves exactly it. Treating that as a
    // failed pull froze lastVerifiedPullAt, and on_stale=fail_closed then
    // bricked a perfectly healthy fleet with deny-all.
    const h = harness(async () => okResult(7, YAML_V2, true), 7);
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.unchanged).toBe(true);
    expect(h.state.lastVerifiedPullAt).toBe(5_000);
    expect(h.state.version).toBe(7);
  });

  test("an unchanged bundle does NOT re-record history or re-clear approval memory when the digest is unchanged", async () => {
    const h = harness(async () => okResult(7, YAML_V2, true), 7);
    h.state.digest = "abc123abc123"; // seed: matches the fetch result's digest -> truly unchanged (F4 case e)
    await refreshOnce(h.deps);
    expect(h.adopted).toEqual([]); // no duplicate history entry every tick
  });

  test("an unchanged bundle still restores the real policy after a fail-closed deny-all swap", async () => {
    const h = harness(async () => okResult(7, YAML_V2, true), 7);
    h.policyStore.reload(denyAllYaml("a", "x")); // staleness tripped fail_closed
    expect(h.policyStore.current.grants.size).toBe(0);
    await refreshOnce(h.deps);
    expect(allowSources(h.policyStore)).toContain("repo:write"); // self-healed
  });

  test("the floor is never lowered by an unchanged bundle", async () => {
    const h = harness(async () => okResult(7, YAML_V2, true), 7);
    await refreshOnce(h.deps);
    expect(h.floorNow()).toBe(7);
  });

  test("a persist failure does not un-adopt a policy already in force", async () => {
    const h = harness(async () => okResult(8, YAML_V2), 7, { acceptThrows: true });
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(true); // the swap happened; only the floor write failed
    expect(allowSources(h.policyStore)).toContain("repo:write");
    expect(h.state.version).toBe(8);
    expect(h.lines.join("\n")).toContain("could not persist the anti-rollback floor");
  });
});

describe("refreshOnce profiles threading", () => {
  const CI_PROFILE_YAML = "agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]";
  const ciProfile: ProfileEntry = { name: "ci", policy: CI_PROFILE_YAML };

  test("a v2 bundle with profiles threads them into reload as the 2nd arg and advances the floor", async () => {
    const h = harness(async () => okResult(9, YAML_V2, false, [ciProfile]), 6);
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(true);
    expect(h.reloadCalls).toHaveLength(1);
    expect(h.reloadCalls[0]?.profiles).toEqual([ciProfile]);
    expect(h.floorNow()).toBe(9);
  });

  test("a bundle whose profile fails to merge does NOT advance the floor and does not call onAdopted", async () => {
    // "not-declared" is not in the harness's declaredNames set (only "ci" is),
    // so the reload's merge step rejects it -- exercising the SAME keep-current
    // path a bad default YAML does, but reached through the profiles arg.
    const badProfile: ProfileEntry = { name: "not-declared", policy: CI_PROFILE_YAML };
    const h = harness(async () => okResult(9, YAML_V2, false, [badProfile]), 6);
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(false);
    expect(h.floorNow()).toBe(6);
    expect(h.adopted).toEqual([]);
    expect(h.state.version).toBe(0);
  });

  test("absent profiles (null) clears any existing profile entries via reload(yaml, [])", async () => {
    const h = harness(async () => okResult(9, YAML_V2), 6); // okResult defaults profiles to null
    await refreshOnce(h.deps);
    expect(h.reloadCalls).toHaveLength(1);
    expect(h.reloadCalls[0]?.profiles).toEqual([]);
  });

  test("F11: a bad PROFILE logs the code + name, NEVER the profile's YAML source", async () => {
    // "ci" IS declared in the harness, so the merge reaches the compile step and
    // fails THERE (parse_error), not on the declared-name check. The broken YAML
    // carries a distinctive marker that must never leak onto the log path.
    const SENTINEL = "s3nt1nel-secret-schedule-regex";
    const badCiYaml = `agent: a\non_behalf_of: x\ngrants: [ "${SENTINEL}"`; // unterminated flow seq → parse error
    const h = harness(async () => okResult(9, YAML_V2, false, [{ name: "ci", policy: badCiYaml }]), 6);
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(false);
    const log = h.lines.join("\n");
    expect(log).toContain("parse_error"); // the fixed reason code
    expect(log).toContain('profile "ci"'); // the profile name
    expect(log).not.toContain(SENTINEL); // profile YAML source never reaches the log (F11)
    // The full YAML-bearing detail is still available to callers via `reason`.
    if (!out.ok) expect(out.reason).toContain("ci");
  });
});

describe("refreshOnce F4: same-version content change still clears approval memory", () => {
  test("unchanged version but a different digest -> onAdopted IS called and state.digest is updated", async () => {
    const h = harness(async () => okResult(7, YAML_V2, true, null, "new-digest-111"), 7);
    h.state.digest = "old-digest-000"; // different content signed under the same accepted version
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.unchanged).toBe(true);
    expect(h.adopted).toEqual([YAML_V2]); // memory cleared + history recorded despite same version
    expect(h.state.digest).toBe("new-digest-111");
  });

  test("unchanged version and the SAME digest -> onAdopted is NOT called", async () => {
    const h = harness(async () => okResult(7, YAML_V2, true, null, "same-digest-222"), 7);
    h.state.digest = "same-digest-222"; // truly unchanged content
    const out = await refreshOnce(h.deps);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.unchanged).toBe(true);
    expect(h.adopted).toEqual([]);
    expect(h.state.digest).toBe("same-digest-222");
  });
});

describe("isStale", () => {
  test("no max_age configured -> never stale", () => {
    expect(isStale({ version: 1, digest: "d", lastVerifiedPullAt: 0 }, undefined, 9_999_999)).toBe(false);
  });
  test("never pulled -> stale once a bound is set", () => {
    expect(isStale({ version: 0, digest: "", lastVerifiedPullAt: 0 }, 60, 61_000)).toBe(true);
  });
  test("a recent verified pull -> fresh", () => {
    expect(isStale({ version: 2, digest: "d", lastVerifiedPullAt: 100_000 }, 60, 130_000)).toBe(false);
  });
  test("older than the bound -> stale", () => {
    expect(isStale({ version: 2, digest: "d", lastVerifiedPullAt: 100_000 }, 60, 161_000)).toBe(true);
  });
});

describe("denyAllYaml", () => {
  test("compiles to a zero-grant policy that denies", () => {
    const c = compilePolicyYaml(denyAllYaml("a", "x"));
    expect(c.ok).toBe(true);
    if (!c.ok) return;
    expect(c.policy.grants.size).toBe(0);
    expect(evaluate(c.policy, { tool: "github", action: "repo:read", target: "acme/api" }).decision).toBe("deny");
  });
  test("quotes identifiers so they cannot break out of the YAML", () => {
    const c = compilePolicyYaml(denyAllYaml('a: evil\ngrants: [{tool: github, allow: ["*"]}]', "x"));
    expect(c.ok).toBe(true);
    if (c.ok) expect(c.policy.grants.size).toBe(0);
  });
});
