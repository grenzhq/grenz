import { describe, expect, it, test } from "bun:test";
import { configSchema, policyProfileSourceSchema } from "./schema.ts";

const HASH = "a".repeat(64);

function baseConfig(over: Record<string, unknown> = {}) {
  return { agents: [{ id: "ci", token_hash: HASH }], ...over };
}

describe("policy_profiles", () => {
  it("parses a valid profiles map and an agent that references one", () => {
    const parsed = configSchema.safeParse(
      baseConfig({
        policy_profiles: { "ci-merge": { file: "profiles/ci.yaml" } },
        agents: [{ id: "ci", token_hash: HASH, policy: "ci-merge" }],
      }),
    );
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.policy_profiles["ci-merge"]).toEqual({ file: "profiles/ci.yaml" });
      expect(parsed.data.agents[0]!.policy).toBe("ci-merge");
    }
  });

  it("defaults policy_profiles to {} when absent", () => {
    const parsed = configSchema.safeParse(baseConfig());
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.policy_profiles).toEqual({});
  });

  it("rejects an agent policy that names an undefined profile", () => {
    const parsed = configSchema.safeParse(
      baseConfig({ agents: [{ id: "ci", token_hash: HASH, policy: "ghost" }] }),
    );
    expect(parsed.success).toBe(false);
  });

  it("rejects a decoy agent that sets policy", () => {
    const parsed = configSchema.safeParse(
      baseConfig({
        policy_profiles: { p: { file: "profiles/p.yaml" } },
        agents: [
          { id: "real", token_hash: HASH },
          { id: "trap", token_hash: "b".repeat(64), decoy: true, policy: "p" },
        ],
      }),
    );
    expect(parsed.success).toBe(false);
  });

  it("rejects an https profile source (local file only in Slice 1)", () => {
    const parsed = configSchema.safeParse(
      baseConfig({ policy_profiles: { p: { file: "https://evil.example/p.yaml" } } }),
    );
    // `file` must be a local path, not a URL scheme.
    expect(parsed.success).toBe(false);
  });

  it("rejects an invalid profile name", () => {
    const parsed = configSchema.safeParse(
      baseConfig({ policy_profiles: { "Bad Name": { file: "profiles/p.yaml" } } }),
    );
    expect(parsed.success).toBe(false);
  });
});

test("name-only: {} and null both parse", () => {
  expect(policyProfileSourceSchema.safeParse({}).success).toBe(true);
  expect(policyProfileSourceSchema.safeParse(null).success).toBe(true);
});
test("a local file parses; a URL file is rejected", () => {
  expect(policyProfileSourceSchema.safeParse({ file: "profiles/ci.yaml" }).success).toBe(true);
  expect(policyProfileSourceSchema.safeParse({ file: "https://x/y.yaml" }).success).toBe(false);
});
