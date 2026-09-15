import { test, expect, describe } from "bun:test";
import { refreshUnsignedOnce, isStale } from "../src/distribution/refresh.ts";
import type { PolicyDistributionState } from "../src/distribution/types.ts";
import { PolicyStore } from "../src/policy/store.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";

/**
 * Unsigned distribution had no refresh loop at all, so `refresh_seconds` and
 * `on_stale` were inert for every proxy without a pinned key — which is every
 * proxy `grenz connect` sets up. The clock these assertions guard is the one
 * staleness acts on: if a failed pull can advance it, fail_closed never fires
 * and the proxy serves local rules forever while claiming otherwise.
 */

const YAML_V1 = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`;
const YAML_V2 = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read, repo:write]`;
const UNCOMPILABLE = `agent: a\ngrants: [[[`;

function compiled(yaml: string) {
  const c = compilePolicyYaml(yaml);
  if (!c.ok) throw new Error(`fixture does not compile: ${c.error}`);
  return c.policy;
}

function allowSources(store: PolicyStore): string[] {
  return (store.current.grants.get("github")?.allow ?? []).map((a) => a.action.source);
}

function harness(fetchPolicy: () => Promise<{ ok: true; policyYaml: string } | { ok: false; error: string }>) {
  const state: PolicyDistributionState = { version: 0, digest: "", lastVerifiedPullAt: 0 };
  const policyStore = new PolicyStore(compiled(YAML_V1), new Set());
  const lines: string[] = [];
  const adopted: string[] = [];
  // A stand-in digest: the assertions are about change DETECTION, not sha256.
  const digestOf = async (yaml: string) => `d${yaml.length}`;
  return {
    state,
    policyStore,
    lines,
    adopted,
    run: () =>
      refreshUnsignedOnce({
        fetchPolicy,
        policyStore,
        state,
        now: () => 1_000_000,
        digestOf,
        emit: (l) => lines.push(l),
        onAdopted: (yaml) => adopted.push(yaml),
      }),
  };
}

describe("refreshUnsignedOnce", () => {
  test("an unreachable plane keeps the live policy and does NOT advance the clock", async () => {
    // The clock is what staleness reads. Advancing it on a failed pull is the
    // fail-open: on_stale would never fire and the proxy would serve stale
    // rules indefinitely.
    const h = harness(async () => ({ ok: false, error: "policy source unreachable" }));
    const out = await h.run();
    expect(out.ok).toBe(false);
    expect(h.state.lastVerifiedPullAt).toBe(0);
    expect(allowSources(h.policyStore)).toEqual(["repo:read"]);
    expect(h.adopted).toEqual([]);
  });

  test("a 401 leaves the clock at zero, so a boot-time rejection reads as infinitely stale", async () => {
    // The exact reported failure: a proxy whose FIRST pull is rejected served
    // local policy.yaml while its config said fail_closed.
    const h = harness(async () => ({ ok: false, error: "policy source returned 401" }));
    await h.run();
    expect(h.state.lastVerifiedPullAt).toBe(0);
    // A real epoch clock, not the harness's small fixture value: `isStale`
    // compares now - 0 against the bound, so a toy `now` is younger than a
    // one-hour max_age and would pass for the wrong reason.
    expect(isStale(h.state, 3600, Date.now())).toBe(true);
  });

  test("a policy that does not compile is refused and the clock stays put", async () => {
    const h = harness(async () => ({ ok: true, policyYaml: UNCOMPILABLE }));
    const out = await h.run();
    expect(out.ok).toBe(false);
    expect(h.state.lastVerifiedPullAt).toBe(0);
    expect(allowSources(h.policyStore)).toEqual(["repo:read"]);
  });

  test("the rejection line never quotes the policy source", async () => {
    // A compile error quotes the policy's own YAML; the log must carry a fixed
    // reason instead (same rule the signed path follows).
    const h = harness(async () => ({ ok: true, policyYaml: UNCOMPILABLE }));
    await h.run();
    expect(h.lines.join("\n")).not.toContain("grants: [[[");
    expect(h.lines.join("\n")).toContain("does not compile");
  });

  test("a good pull swaps the policy, advances the clock, and records history", async () => {
    const h = harness(async () => ({ ok: true, policyYaml: YAML_V2 }));
    const out = await h.run();
    expect(out).toMatchObject({ ok: true, unchanged: false });
    expect(h.state.lastVerifiedPullAt).toBe(1_000_000);
    expect(allowSources(h.policyStore)).toEqual(["repo:read", "repo:write"]);
    expect(h.adopted).toEqual([YAML_V2]);
  });

  test("re-serving the same policy advances the clock but does not re-record it", async () => {
    // The steady state between policy changes. It must still tick the clock —
    // that is what heals a proxy swapped to deny-all for staleness — without
    // re-clearing remembered approvals on every refresh.
    const h = harness(async () => ({ ok: true, policyYaml: YAML_V2 }));
    await h.run();
    h.adopted.length = 0;
    h.state.lastVerifiedPullAt = 0;
    const out = await h.run();
    expect(out).toMatchObject({ ok: true, unchanged: true });
    expect(h.state.lastVerifiedPullAt).toBe(1_000_000);
    expect(h.adopted).toEqual([]);
  });

  test("a proxy that has never pulled is stale against any bound", async () => {
    const state: PolicyDistributionState = { version: 0, digest: "", lastVerifiedPullAt: 0 };
    expect(isStale(state, 30, Date.now())).toBe(true);
    expect(isStale(state, 604800, Date.now())).toBe(true);
  });
});
