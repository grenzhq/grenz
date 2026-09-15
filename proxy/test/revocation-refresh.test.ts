import { test, expect, describe } from "bun:test";
import {
  refreshRevocationsOnce,
  isRevocationStale,
  type RevocationRefreshDeps,
} from "../src/revocation/refresh.ts";
import type { RevocationDistributionState } from "../src/revocation/types.ts";
import type { RevocationFetchResult } from "../src/revocation/source.ts";

function freshState(): RevocationDistributionState {
  return { version: 0, count: 0, expiresAt: null, lastVerifiedPullAt: 0, staleClosed: false };
}

function fakeStore(floor: number) {
  const calls: Array<{ agents: readonly string[]; version: number; expiresAt: number | null }> = [];
  return {
    floor: () => floor,
    replace: (agents: readonly string[], version: number, expiresAt: number | null) => {
      calls.push({ agents, version, expiresAt });
    },
    calls,
  };
}

function deps(
  fetchResult: RevocationFetchResult,
  store: Pick<RevocationRefreshDeps["store"], "floor" | "replace">,
  state: RevocationDistributionState,
  lines: string[],
  now = 5000,
): RevocationRefreshDeps {
  return {
    fetchSet: async () => fetchResult,
    store,
    state,
    now: () => now,
    emit: (l) => lines.push(l),
  };
}

describe("refreshRevocationsOnce", () => {
  test("adopts a newer set: swaps, advances state", async () => {
    const store = fakeStore(3);
    const state = freshState();
    const lines: string[] = [];
    const out = await refreshRevocationsOnce(
      deps({ ok: true, version: 4, revokedAgents: ["a", "b"], expiresAt: 999, unchanged: false }, store, state, lines),
    );
    expect(out).toEqual({ ok: true, version: 4, count: 2, unchanged: false });
    expect(store.calls).toHaveLength(1);
    expect(state.version).toBe(4);
    expect(state.count).toBe(2);
    expect(state.expiresAt).toBe(999);
    expect(state.lastVerifiedPullAt).toBe(5000);
  });

  test("unchanged re-serve: advances the liveness clock but does NOT re-persist", async () => {
    const store = fakeStore(4);
    const state = freshState();
    const out = await refreshRevocationsOnce(
      deps({ ok: true, version: 4, revokedAgents: ["a"], expiresAt: null, unchanged: true }, store, state, []),
    );
    expect(out).toEqual({ ok: true, version: 4, count: 1, unchanged: true });
    expect(store.calls).toHaveLength(0); // no re-write
    expect(state.lastVerifiedPullAt).toBe(5000);
  });

  test("unchanged re-serve does NOT overwrite count/expiresAt from the (unpersisted) fetched doc", async () => {
    const store = fakeStore(4);
    const state = freshState();
    // State already reflects the persisted/enforced set: 7 agents, expiry 123.
    state.version = 4;
    state.count = 7;
    state.expiresAt = 123;
    // A plane re-serves v4 but with DIFFERENT count/expiry (only possible via
    // signer misuse — a compromised plane can only replay the exact bytes). The
    // enforced set is authoritative; the fetched doc must not move the clock/gauge.
    const out = await refreshRevocationsOnce(
      deps({ ok: true, version: 4, revokedAgents: ["a"], expiresAt: 999, unchanged: true }, store, state, []),
    );
    expect(out.ok).toBe(true);
    expect(store.calls).toHaveLength(0);
    expect(state.count).toBe(7); // preserved, NOT 1
    expect(state.expiresAt).toBe(123); // preserved, NOT 999
    expect(state.lastVerifiedPullAt).toBe(5000); // liveness clock still advanced
  });

  test("fetch failure: keeps cached set, state untouched", async () => {
    const store = fakeStore(4);
    const state = freshState();
    state.version = 4;
    state.lastVerifiedPullAt = 1000;
    const lines: string[] = [];
    const out = await refreshRevocationsOnce(
      deps({ ok: false, error: "revocation source unreachable" }, store, state, lines),
    );
    expect(out.ok).toBe(false);
    expect(store.calls).toHaveLength(0);
    expect(state.lastVerifiedPullAt).toBe(1000); // frozen — no un-revoke
    expect(lines[0]).toContain("keeping the cached set");
  });

  test("persist failure: does NOT advance state (stays fail-static)", async () => {
    const store = {
      floor: () => 3,
      replace: () => {
        throw new Error("disk full");
      },
    };
    const state = freshState();
    state.lastVerifiedPullAt = 1000;
    const out = await refreshRevocationsOnce(
      deps({ ok: true, version: 4, revokedAgents: ["a"], expiresAt: null, unchanged: false }, store, state, []),
    );
    expect(out).toEqual({ ok: false, reason: "persist_failed" });
    expect(state.lastVerifiedPullAt).toBe(1000);
  });
});

describe("isRevocationStale", () => {
  const base = (): RevocationDistributionState => ({
    version: 4,
    count: 1,
    expiresAt: null,
    lastVerifiedPullAt: 10_000,
    staleClosed: false,
  });

  test("no bound + no expiry -> never stale", () => {
    expect(isRevocationStale(base(), undefined, 10_000_000)).toBe(false);
  });

  test("pull older than the age bound -> stale", () => {
    expect(isRevocationStale(base(), 60, 10_000 + 61_000)).toBe(true);
  });

  test("pull within the age bound -> fresh", () => {
    expect(isRevocationStale(base(), 60, 10_000 + 59_000)).toBe(false);
  });

  test("expired envelope -> stale even with no age bound", () => {
    const s = base();
    s.expiresAt = 100; // epoch seconds
    expect(isRevocationStale(s, undefined, 200_000)).toBe(true); // 200s > 100s
  });

  test("unexpired envelope -> fresh", () => {
    const s = base();
    s.expiresAt = 1_000_000; // seconds
    expect(isRevocationStale(s, undefined, 500_000_000)).toBe(false); // 500_000s < 1_000_000s
  });
});
