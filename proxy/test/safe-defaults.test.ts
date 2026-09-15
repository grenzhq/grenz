import { test, expect, describe } from "bun:test";
import { buildSafeDefaults, renderPolicyYaml, type SafeGrant } from "../src/policy/safe-defaults.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";

const gh = [{ name: "github", type: "github" }];

function grant(grants: SafeGrant[], tool: string): SafeGrant {
  const g = grants.find((x) => x.tool === tool);
  if (!g) throw new Error(`no grant for ${tool}`);
  return g;
}

describe("buildSafeDefaults", () => {
  test("github / normal: only the irreversible + unmapped-write actions ask", () => {
    const g = grant(buildSafeDefaults(gh, "normal"), "github");
    expect(g.require_approval).toEqual(["actions:write", "api:write", "pr:merge", "repo:delete"]);
    // routine work is allowed outright
    expect(g.allow).toContain("repo:read");
    expect(g.allow).toContain("pr:create");
    expect(g.allow).toContain("pr:comment"); // sensitive but allowed in normal
    expect(g.allow).toContain("repo:write");
    expect(g.allow).not.toContain("pr:merge");
  });

  test("github / strict: sensitive edits also ask", () => {
    const g = grant(buildSafeDefaults(gh, "strict"), "github");
    for (const a of ["pr:comment", "issue:update", "pr:update", "repo:write"]) {
      expect(g.require_approval).toContain(a);
    }
    expect(g.allow).toContain("repo:read");
    expect(g.allow).not.toContain("pr:comment");
  });

  test("slack: exfil (file:upload) always asks; unknown tools ask via call:*", () => {
    const g = grant(buildSafeDefaults([{ name: "slack", type: "slack" }], "normal"), "slack");
    expect(g.require_approval).toContain("file:upload");
    expect(g.require_approval).toContain("call:*");
    expect(g.allow).toContain("message:send");
  });

  test("generic mcp: allow + observe (call:*), nothing forced to approval", () => {
    const g = grant(buildSafeDefaults([{ name: "notion", type: "mcp" }], "normal"), "notion");
    expect(g.allow).toEqual(["call:*"]);
    expect(g.require_approval).toEqual([]);
  });

  test("NEVER emits a deny — the whole point (ask, don't break the agent)", () => {
    for (const pref of ["normal", "strict"] as const) {
      for (const g of buildSafeDefaults(
        [{ name: "github", type: "github" }, { name: "slack", type: "slack" }, { name: "x", type: "mcp" }],
        pref,
      )) {
        // SafeGrant has no deny field at all; assert the shape stays that way.
        expect(Object.keys(g).sort()).toEqual(["allow", "require_approval", "tool"]);
      }
    }
  });

  test("destructive/exfil are ALWAYS in require_approval, both preferences", () => {
    for (const pref of ["normal", "strict"] as const) {
      const g = grant(buildSafeDefaults(gh, pref), "github");
      for (const a of ["pr:merge", "repo:delete", "actions:write"]) {
        expect(g.require_approval).toContain(a);
        expect(g.allow).not.toContain(a);
      }
    }
  });
});

describe("renderPolicyYaml", () => {
  test("the generated policy compiles through the real engine", () => {
    const grants = buildSafeDefaults(
      [{ name: "github", type: "github" }, { name: "notion", type: "mcp" }],
      "normal",
    );
    const yaml = renderPolicyYaml(grants, { agent: "claude-code", onBehalfOf: "you@example.com", preference: "normal" });
    const compiled = compilePolicyYaml(yaml);
    expect(compiled.ok).toBe(true);
  });

  test("wildcard actions are quoted so the YAML is valid", () => {
    const grants = buildSafeDefaults([{ name: "notion", type: "mcp" }], "normal");
    const yaml = renderPolicyYaml(grants, { agent: "a", onBehalfOf: "x", preference: "normal" });
    expect(yaml).toContain('"call:*"');
  });

  test("ships the kill-switch as commented, discoverable, opt-in guidance", () => {
    const grants = buildSafeDefaults([{ name: "github", type: "github" }], "normal");
    const yaml = renderPolicyYaml(grants, { agent: "claude-code", onBehalfOf: "x", preference: "normal" });
    // The guidance is present and points at both tripwires and decoys…
    expect(yaml).toContain("# tripwires:");
    expect(yaml).toContain("grenz decoy");
    expect(yaml).toContain("on_trip: leaf");
    // …but left commented, so a fresh policy compiles with NO active tripwire
    // (an armed cascade default would break an honest agent — never a default).
    const compiled = compilePolicyYaml(yaml);
    if (!compiled.ok) throw new Error(compiled.error);
    expect(compiled.policy.tripwires).toEqual([]);
  });
});
