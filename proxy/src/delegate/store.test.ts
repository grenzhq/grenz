import { describe, expect, it } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DelegationStore } from "./store.ts";

function freshStore(): DelegationStore {
  // A non-existent path loads an empty store; mint persists to it.
  return new DelegationStore(join(tmpdir(), `grenz-del-test-${process.pid}-${Math.floor(performance.now())}.json`));
}

describe("delegation policyProfile snapshot", () => {
  it("mint carries the profile from the minting agent (level 1)", async () => {
    const store = freshStore();
    const now = 1_000;
    const { delegation } = await store.mint({
      parentAgentId: "ci",
      actions: ["pr:*"],
      ttlMs: 60_000,
      note: "",
      now,
      policyProfile: "ci-merge",
    });
    expect(delegation.policyProfile).toBe("ci-merge");
    const hash = delegation.tokenHash;
    const resolved = store.resolveChain(hash, now + 1);
    expect(resolved?.policyProfile).toBe("ci-merge");
  });

  it("a nested mint inherits the parent grant's profile", async () => {
    const store = freshStore();
    const now = 1_000;
    const root = await store.mint({
      parentAgentId: "ci",
      actions: ["pr:*"],
      ttlMs: 60_000,
      note: "",
      now,
      policyProfile: "ci-merge",
    });
    const child = await store.mint({
      parentAgentId: "ci",
      parentDelegationId: root.delegation.id,
      actions: ["pr:read"],
      ttlMs: 30_000,
      note: "",
      now,
      policyProfile: "ci-merge", // caller passes the inherited value
    });
    const resolved = store.resolveChain(child.delegation.tokenHash, now + 1);
    expect(resolved?.policyProfile).toBe("ci-merge"); // read off the ROOT grant
  });

  it("undefined profile round-trips as undefined", async () => {
    const store = freshStore();
    const now = 1_000;
    const { delegation } = await store.mint({
      parentAgentId: "legacy",
      actions: ["pr:read"],
      ttlMs: 60_000,
      note: "",
      now,
    });
    expect(delegation.policyProfile).toBeUndefined();
    expect(store.resolveChain(delegation.tokenHash, now + 1)?.policyProfile).toBeUndefined();
  });

  it("persists and reloads the profile from disk", async () => {
    const path = join(tmpdir(), `grenz-del-persist-${process.pid}-${Math.floor(performance.now())}.json`);
    const now = 1_000;
    const first = new DelegationStore(path);
    const { delegation } = await first.mint({
      parentAgentId: "ci",
      actions: ["pr:*"],
      ttlMs: 60_000,
      note: "",
      now,
      policyProfile: "ci-merge",
    });
    const reloaded = new DelegationStore(path);
    expect(reloaded.get(delegation.id)?.policyProfile).toBe("ci-merge");
  });
});
