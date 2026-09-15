import { test, expect, describe } from "bun:test";
import { policyEditorView, writeGrants, type EditorGrant } from "../src/policy/editor.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { parse as parseYaml } from "yaml";

const FULL = `agent: claude-code
on_behalf_of: you@example.com
grants:
  - tool: github
    allow:
      - repo:read
      - pr:read
    require_approval:
      - issue:update
    deny:
      - pr:merge
budget:
  max_actions_per_hour: 200
  per_upstream:
    github: 100
tripwires:
  - action: repo:delete
schedule:
  timezone: UTC
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"
      end: "18:00"
`;

describe("policyEditorView", () => {
  test("extracts grants with all three lists", () => {
    const v = policyEditorView(FULL);
    expect(v.grants).toHaveLength(1);
    const g = v.grants[0]!;
    expect(g.tool).toBe("github");
    expect(g.allow).toEqual(["repo:read", "pr:read"]);
    expect(g.require_approval).toEqual(["issue:update"]);
    expect(g.deny).toEqual(["pr:merge"]);
  });

  test("lists the advanced sections it will preserve, not edit", () => {
    const v = policyEditorView(FULL);
    expect(v.advancedSections.sort()).toEqual(["budget", "schedule", "tripwires"]);
  });

  test("a grant with missing lists yields empty arrays, not undefined", () => {
    const v = policyEditorView("agent: a\non_behalf_of: x\ngrants:\n  - tool: slack\n    allow: [chat:post]\n");
    expect(v.grants[0]!.require_approval).toEqual([]);
    expect(v.grants[0]!.deny).toEqual([]);
  });

  test("target-scoped object entries are kept, not flattened", () => {
    const src = `agent: a
on_behalf_of: x
grants:
  - tool: github
    allow:
      - repo:read
      - action: pr:create
        targets: ["octocat/*"]
`;
    const v = policyEditorView(src);
    expect(v.grants[0]!.allow[0]).toBe("repo:read");
    expect(v.grants[0]!.allow[1]).toEqual({ action: "pr:create", targets: ["octocat/*"] });
  });
});

describe("writeGrants — round-trip safety", () => {
  test("advanced sections survive a grants edit", () => {
    const grants: EditorGrant[] = [
      { tool: "github", allow: ["repo:read", "pr:read", "pr:create"], require_approval: [], deny: ["pr:merge"] },
    ];
    const out = writeGrants(FULL, grants);
    const obj = parseYaml(out) as Record<string, unknown>;
    // budget / tripwires / schedule are byte-preserved (structurally).
    expect(obj.budget).toEqual({ max_actions_per_hour: 200, per_upstream: { github: 100 } });
    expect(obj.tripwires).toEqual([{ action: "repo:delete" }]);
    expect((obj.schedule as Record<string, unknown>).timezone).toBe("UTC");
    // agent / on_behalf_of unchanged.
    expect(obj.agent).toBe("claude-code");
    // the edit landed.
    const g = (obj.grants as Array<Record<string, unknown>>)[0]!;
    expect(g.allow).toEqual(["repo:read", "pr:read", "pr:create"]);
  });

  test("the result compiles through the real engine", () => {
    const grants: EditorGrant[] = [
      { tool: "github", allow: ["repo:read"], require_approval: [], deny: ["repo:delete"] },
    ];
    const out = writeGrants(FULL, grants);
    const r = compilePolicyYaml(out);
    expect(r.ok).toBe(true);
  });

  test("empty lists are dropped but the tool is kept", () => {
    const out = writeGrants(FULL, [{ tool: "slack", allow: [], require_approval: [], deny: [] }]);
    const obj = parseYaml(out) as Record<string, unknown>;
    const g = (obj.grants as Array<Record<string, unknown>>)[0]!;
    expect(g).toEqual({ tool: "slack" });
  });

  test("object (target-scoped) entries round-trip losslessly", () => {
    const grants: EditorGrant[] = [
      { tool: "github", allow: ["repo:read", { action: "pr:create", targets: ["o/*"] }], require_approval: [], deny: [] },
    ];
    const out = writeGrants("agent: a\non_behalf_of: x\ngrants: []\n", grants);
    const back = policyEditorView(out);
    expect(back.grants[0]!.allow).toEqual(["repo:read", { action: "pr:create", targets: ["o/*"] }]);
    expect(compilePolicyYaml(out).ok).toBe(true);
  });

  test("comments on advanced sections survive a grants edit", () => {
    const withComments = `agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: [repo:read]
budget:
  # keep this low until we trust the agent
  max_actions_per_hour: 50
`;
    const out = writeGrants(withComments, [{ tool: "github", allow: ["repo:read", "pr:read"], require_approval: [], deny: [] }]);
    expect(out).toContain("# keep this low until we trust the agent");
    const obj = parseYaml(out) as Record<string, unknown>;
    expect((obj.budget as Record<string, unknown>).max_actions_per_hour).toBe(50);
  });

  test("adding a whole new tool preserves the existing one", () => {
    const view = policyEditorView(FULL);
    const grants = [...view.grants, { tool: "slack", allow: ["chat:post"], require_approval: [], deny: [] }];
    const out = writeGrants(FULL, grants);
    const obj = parseYaml(out) as Record<string, unknown>;
    const tools = (obj.grants as Array<Record<string, unknown>>).map((g) => g.tool);
    expect(tools).toEqual(["github", "slack"]);
  });
});
