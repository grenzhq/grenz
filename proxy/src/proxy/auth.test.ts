import { describe, expect, it } from "bun:test";
import { resolvePrincipal } from "./auth.ts";
import { agentSchema, type AgentConfig } from "../config/schema.ts";
import { hashToken } from "../util/token.ts";
import { DelegationStore } from "../delegate/store.ts";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function agent(id: string, token: string, policy?: string): Promise<AgentConfig> {
  return agentSchema.parse({
    id,
    token_hash: await hashToken(token),
    ...(policy ? { policy } : {}),
  });
}

describe("resolvePrincipal policyProfile", () => {
  it("agent principal carries its configured policy", async () => {
    const a = await agent("ci", "tok-ci", "ci-merge");
    const res = await resolvePrincipal([a], null, "tok-ci", 1_000);
    expect(res.principal?.kind).toBe("agent");
    expect(res.principal?.policyProfile).toBe("ci-merge");
  });

  it("agent with no policy → undefined", async () => {
    const a = await agent("legacy", "tok-legacy");
    const res = await resolvePrincipal([a], null, "tok-legacy", 1_000);
    expect(res.principal?.policyProfile).toBeUndefined();
  });

  it("delegation principal carries the profile SNAPSHOTTED at mint, not the root's live one", async () => {
    const store = new DelegationStore(
      join(tmpdir(), `grenz-auth-test-${process.pid}-${Math.floor(performance.now())}.json`),
    );
    const now = 1_000;
    const { token } = await store.mint({
      parentAgentId: "ci",
      actions: ["pr:*"],
      ttlMs: 60_000,
      note: "",
      now,
      policyProfile: "ci-merge",
    });
    // The root is present but its config profile has since been retargeted. The
    // sub-token must keep the profile it was minted under — a live lookup here
    // would let an edit to the parent silently repoint an existing sub-token.
    const rootRetargeted = await agent("ci", "tok-ci", "ci-readonly");
    const res = await resolvePrincipal([rootRetargeted], store, token, now + 1);
    expect(res.principal?.kind).toBe("delegation");
    expect(res.principal?.policyProfile).toBe("ci-merge");
  });

  it("delegation whose root agent is gone resolves to NO principal (fail closed)", async () => {
    const store = new DelegationStore(
      join(tmpdir(), `grenz-auth-orphan-${process.pid}-${Math.floor(performance.now())}.json`),
    );
    const now = 1_000;
    const { token } = await store.mint({
      parentAgentId: "ci",
      actions: ["pr:*"],
      ttlMs: 60_000,
      note: "",
      now,
      policyProfile: "ci-merge",
    });
    // Nothing left to attenuate from: a sub-token is only ever a narrowing of
    // its root, so a removed root kills it rather than un-scoping it.
    const res = await resolvePrincipal([], store, token, now + 1);
    expect(res.principal).toBeNull();
    expect(res.orphanRootAgentId).toBe("ci");
  });
});
