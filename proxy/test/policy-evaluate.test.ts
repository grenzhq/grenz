import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, compilePolicyObject, type CompiledPolicy } from "../src/policy/compile.ts";
import { evaluate } from "../src/policy/evaluate.ts";
import type { Decision, ReasonCode } from "../src/policy/types.ts";

// A policy exercising every precedence path: deny > require_approval > allow,
// glob patterns, default-deny within a grant, and no-grant-for-tool.
const POLICY_YAML = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read, pr:read, pr:create, pr:comment, "issue:*"]
    deny: [pr:merge, repo:delete, "actions:*"]
    require_approval: ["issue:delete"]
  - tool: linear
    allow: ["session:*", "tools:list", "call:list_*", "call:get_*"]
    require_approval: ["call:delete_*"]
    deny: ["call:*_admin"]
  - tool: scoped
    allow:
      - repo:read
      - action: "pr:*"
        targets: ["/repos/acme/*"]
    deny:
      - action: repo:archive
        targets: ["/repos/prod-*"]
    require_approval:
      - action: "release:*"
        targets: ["/repos/infra/*"]
budget:
  max_actions_per_hour: 200
`;

function loadPolicy(): CompiledPolicy {
  const result = compilePolicyYaml(POLICY_YAML);
  if (!result.ok) throw new Error(result.error);
  return result.policy;
}

const policy = loadPolicy();

interface Case {
  readonly name: string;
  readonly tool: string;
  readonly action: string;
  readonly target?: string | null;
  readonly decision: Decision;
  readonly reason: ReasonCode;
  readonly pattern?: string;
}

const CASES: readonly Case[] = [
  // --- allow paths ---
  { name: "explicit allow (exact)", tool: "github", action: "repo:read", decision: "allow", reason: "explicit_allow", pattern: "repo:read" },
  { name: "allow pr:create", tool: "github", action: "pr:create", decision: "allow", reason: "explicit_allow", pattern: "pr:create" },
  { name: "allow pr:comment", tool: "github", action: "pr:comment", decision: "allow", reason: "explicit_allow", pattern: "pr:comment" },
  { name: "allow via glob issue:*", tool: "github", action: "issue:create", decision: "allow", reason: "explicit_allow", pattern: "issue:*" },
  { name: "allow issue:read via glob", tool: "github", action: "issue:read", decision: "allow", reason: "explicit_allow", pattern: "issue:*" },

  // --- deny paths (explicit) ---
  { name: "explicit deny pr:merge", tool: "github", action: "pr:merge", decision: "deny", reason: "explicit_deny", pattern: "pr:merge" },
  { name: "explicit deny repo:delete", tool: "github", action: "repo:delete", decision: "deny", reason: "explicit_deny", pattern: "repo:delete" },
  { name: "deny via glob actions:*", tool: "github", action: "actions:read", decision: "deny", reason: "explicit_deny", pattern: "actions:*" },
  { name: "deny actions:write via glob", tool: "github", action: "actions:write", decision: "deny", reason: "explicit_deny", pattern: "actions:*" },

  // --- require_approval path ---
  { name: "require_approval issue:delete", tool: "github", action: "issue:delete", decision: "require_approval", reason: "approval_required", pattern: "issue:delete" },

  // --- precedence: approval beats allow (issue:delete matches both issue:* allow and issue:delete approval) ---
  // covered by the case above; approval must win.

  // --- precedence: deny beats approval (call:delete_admin matches deny call:*_admin AND approval call:delete_*) ---
  { name: "deny beats approval", tool: "linear", action: "call:delete_admin", decision: "deny", reason: "explicit_deny", pattern: "call:*_admin" },
  { name: "linear approval call:delete_*", tool: "linear", action: "call:delete_issue", decision: "require_approval", reason: "approval_required", pattern: "call:delete_*" },
  { name: "linear allow call:list_*", tool: "linear", action: "call:list_issues", decision: "allow", reason: "explicit_allow", pattern: "call:list_*" },
  { name: "linear allow session:*", tool: "linear", action: "session:initialize", decision: "allow", reason: "explicit_allow", pattern: "session:*" },

  // --- default-deny within a grant (matched nothing) ---
  { name: "default deny: unlisted github action", tool: "github", action: "pr:update", decision: "deny", reason: "no_matching_allow" },
  { name: "default deny: unknown github action", tool: "github", action: "totally:unknown", decision: "deny", reason: "no_matching_allow" },
  { name: "default deny: linear unlisted call", tool: "linear", action: "call:create_issue", decision: "deny", reason: "no_matching_allow" },

  // --- no grant for the tool ---
  { name: "no grant: slack", tool: "slack", action: "message:send", decision: "deny", reason: "no_grant_for_tool" },
  { name: "no grant: empty tool", tool: "", action: "x", decision: "deny", reason: "no_grant_for_tool" },

  // --- target-scoped rules (tool: scoped) — enforcement ---
  { name: "scoped allow: target matches", tool: "scoped", action: "pr:create", target: "/repos/acme/web/pulls", decision: "allow", reason: "explicit_allow", pattern: "pr:*" },
  { name: "scoped allow: target misses -> default deny", tool: "scoped", action: "pr:create", target: "/repos/other/web/pulls", decision: "deny", reason: "no_matching_allow" },
  { name: "unscoped rule ignores target", tool: "scoped", action: "repo:read", target: "/repos/anything/at/all", decision: "allow", reason: "explicit_allow", pattern: "repo:read" },
  { name: "scoped deny fires on its target", tool: "scoped", action: "repo:archive", target: "/repos/prod-api", decision: "deny", reason: "explicit_deny", pattern: "repo:archive" },
  { name: "scoped deny misses elsewhere -> falls through to default deny", tool: "scoped", action: "repo:archive", target: "/repos/sandbox", decision: "deny", reason: "no_matching_allow" },
  { name: "scoped require_approval on its target", tool: "scoped", action: "release:create", target: "/repos/infra/deploy", decision: "require_approval", reason: "approval_required", pattern: "release:*" },
  { name: "scoped approval misses -> default deny", tool: "scoped", action: "release:create", target: "/repos/docs", decision: "deny", reason: "no_matching_allow" },
  { name: "batch target does not satisfy scoped rules", tool: "scoped", action: "pr:create", target: "batch(3)", decision: "deny", reason: "no_matching_allow" },

  // --- reachability mode (target: null) ---
  { name: "reachability: scoped allow counts as matchable", tool: "scoped", action: "pr:create", target: null, decision: "allow", reason: "explicit_allow", pattern: "pr:*" },
  { name: "reachability: scoped deny is evadable, skipped", tool: "scoped", action: "repo:archive", target: null, decision: "deny", reason: "no_matching_allow" },
  { name: "reachability: scoped approval reachable", tool: "scoped", action: "release:create", target: null, decision: "require_approval", reason: "approval_required", pattern: "release:*" },
];

describe("policy engine (table-driven)", () => {
  for (const c of CASES) {
    test(c.name, () => {
      const result = evaluate(policy, { tool: c.tool, action: c.action, target: c.target ?? null });
      expect(result.decision).toBe(c.decision);
      expect(result.reason).toBe(c.reason);
      if (c.pattern !== undefined) {
        expect(result.pattern).toBe(c.pattern);
      }
    });
  }

  test("deny-by-default: an empty policy denies everything", () => {
    const empty = compilePolicyYaml(`agent: a\non_behalf_of: b\ngrants: []`);
    expect(empty.ok).toBe(true);
    if (!empty.ok) return;
    const r = evaluate(empty.policy, { tool: "github", action: "repo:read", target: null });
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("no_grant_for_tool");
  });

  test("deny-by-default: a grant with no allow denies its own tool", () => {
    const p = compilePolicyYaml(
      `agent: a\non_behalf_of: b\ngrants:\n  - tool: github\n    deny: [pr:merge]`,
    );
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    const r = evaluate(p.policy, { tool: "github", action: "repo:read", target: null });
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("no_matching_allow");
  });

  test("evaluation is pure: same input, same output, no mutation", () => {
    const a = evaluate(policy, { tool: "github", action: "repo:read", target: null });
    const b = evaluate(policy, { tool: "github", action: "repo:read", target: null });
    expect(a).toEqual(b);
  });

  test("a deny that matched a rule with a message carries it", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", deny: [{ action: "pr:merge", message: "open a PR instead" }] }],
    });
    if (!r.ok) throw new Error(r.error);
    const out = evaluate(r.policy, { tool: "github", action: "pr:merge", target: "/x" });
    expect(out.decision).toBe("deny");
    expect(out.message).toBe("open a PR instead");
  });

  test("first-match deny rule's message wins when several globs match", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [
        {
          tool: "github",
          deny: [
            { action: "pr:merge", message: "specific" },
            { action: "pr:*", message: "broad" },
          ],
        },
      ],
    });
    if (!r.ok) throw new Error(r.error);
    expect(evaluate(r.policy, { tool: "github", action: "pr:merge", target: "/x" }).message).toBe("specific");
  });

  test("a deny with no message, an allow, and a no-match carry no message", () => {
    const r = compilePolicyObject({
      agent: "a",
      on_behalf_of: "b",
      grants: [{ tool: "github", allow: ["repo:read"], deny: ["pr:merge"] }],
    });
    if (!r.ok) throw new Error(r.error);
    expect(evaluate(r.policy, { tool: "github", action: "pr:merge", target: "/x" }).message).toBeUndefined();
    expect(evaluate(r.policy, { tool: "github", action: "repo:read", target: "/x" }).message).toBeUndefined();
    expect(evaluate(r.policy, { tool: "github", action: "nope:x", target: "/x" }).message).toBeUndefined();
  });
});
