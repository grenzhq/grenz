import { test, expect, describe } from "bun:test";
import { templateRegistry } from "../src/registry/templates.ts";
import { applyTemplate } from "../src/registry/apply.ts";
import { compilePolicyObject } from "../src/policy/compile.ts";
import { configSchema } from "../src/config/schema.ts";

const baseConfig = () => ({
  listen: { host: "127.0.0.1", port: 8787 },
  upstreams: {},
  agents: [{ id: "claude-code", token_hash: "a".repeat(64) }],
});
const basePolicy = () => ({ agent: "claude-code", on_behalf_of: "you@example.com", grants: [] });

describe("template registry", () => {
  test("list + get", () => {
    expect(templateRegistry.list().length).toBeGreaterThan(0);
    expect(templateRegistry.list("github").every((t) => t.type === "github")).toBe(true);
    expect(templateRegistry.get("github", "safe-defaults")?.type).toBe("github");
    expect(templateRegistry.get("github", "nope")).toBeUndefined();
  });

  test("every bundled template produces a compilable grant", () => {
    for (const t of templateRegistry.list()) {
      const result = applyTemplate({
        configObj: baseConfig(),
        policyObj: basePolicy(),
        upstreamName: t.type,
        credentialKey: `${t.type}_token`,
        template: t,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      expect(configSchema.safeParse(result.config).success).toBe(true);
      const compiled = compilePolicyObject(result.policy);
      expect(compiled.ok).toBe(true);
    }
  });

  test("applyTemplate adds the upstream and the grant", () => {
    const t = templateRegistry.get("github", "safe-defaults")!;
    const result = applyTemplate({
      configObj: baseConfig(),
      policyObj: basePolicy(),
      upstreamName: "github",
      credentialKey: "github_token",
      template: t,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.upstreams?.github).toEqual({
      type: "github",
      base_url: "https://api.github.com",
      credential: "github_token",
    });
    const grant = result.policy.grants?.find((g) => g.tool === "github");
    expect(grant?.deny).toContain("pr:merge");
    expect(grant?.allow).toContain("repo:read");
  });

  test("errors when a grant for the tool already exists", () => {
    const policy = { ...basePolicy(), grants: [{ tool: "github", allow: ["repo:read"] }] };
    const result = applyTemplate({
      configObj: baseConfig(),
      policyObj: policy,
      upstreamName: "github",
      credentialKey: "github_token",
      template: templateRegistry.get("github", "safe-defaults")!,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("already has a grant");
  });

  test("errors on upstream type conflict", () => {
    const config = {
      ...baseConfig(),
      upstreams: { github: { type: "mcp", base_url: "https://x", credential: "k" } },
    };
    const result = applyTemplate({
      configObj: config,
      policyObj: basePolicy(),
      upstreamName: "github",
      credentialKey: "github_token",
      template: templateRegistry.get("github", "safe-defaults")!,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("already exists with type");
  });

  test("applyTemplate does not mutate its inputs (pure)", () => {
    const config = baseConfig();
    const policy = basePolicy();
    applyTemplate({
      configObj: config,
      policyObj: policy,
      upstreamName: "github",
      credentialKey: "github_token",
      template: templateRegistry.get("github", "safe-defaults")!,
    });
    expect(Object.keys(config.upstreams).length).toBe(0);
    expect(policy.grants.length).toBe(0);
  });
});
