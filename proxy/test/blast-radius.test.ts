import { test, expect, describe } from "bun:test";
import { compilePolicyObject } from "../src/policy/compile.ts";
import { analyzeBlastRadius, type DelegationLike } from "../src/blast-radius/analyze.ts";

function policy(grants: Array<{ tool: string; allow?: string[]; deny?: string[]; require_approval?: string[] }>) {
  const compiled = compilePolicyObject({ agent: "claude-code", on_behalf_of: "am@team.dev", grants });
  if (!compiled.ok) throw new Error(compiled.error);
  return compiled.policy;
}

const NO_DELEGATIONS: DelegationLike[] = [];

describe("blast-radius: reachability per upstream", () => {
  test("narrow grant: exact matches split into auto-allow / requires-approval, no broad-grant flag", () => {
    const p = policy([{ tool: "github", allow: ["repo:read", "pr:create"], require_approval: ["issue:update"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    const gh = report.upstreams.find((u) => u.upstream === "github")!;
    expect(gh.enumerable).toBe(true);
    expect(gh.autoAllow).toEqual(["pr:create", "repo:read"]);
    expect(gh.requiresApproval).toEqual(["issue:update"]);
    expect(gh.broadGrants).toEqual([]);
  });

  test("broad glob allow is flagged with its full expansion", () => {
    const p = policy([{ tool: "github", allow: ["repo:*"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    const gh = report.upstreams.find((u) => u.upstream === "github")!;
    expect(gh.broadGrants).toHaveLength(1);
    expect(gh.broadGrants[0]!.pattern).toBe("repo:*");
    expect(gh.broadGrants[0]!.matches).toEqual(
      expect.arrayContaining(["repo:read", "repo:write", "repo:delete"]),
    );
  });

  test("deny overrides a matching allow for the same action", () => {
    const p = policy([{ tool: "github", allow: ["pr:*"], deny: ["pr:merge"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    const gh = report.upstreams.find((u) => u.upstream === "github")!;
    expect(gh.autoAllow).not.toContain("pr:merge");
    expect(gh.autoAllow).toContain("pr:create");
  });

  test("generic mcp upstream is not enumerable — raw patterns only", () => {
    const p = policy([{ tool: "mcp", allow: ["call:get_issue", "session:*"], require_approval: ["call:delete_*"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { mcp: { type: "mcp" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    const mcp = report.upstreams.find((u) => u.upstream === "mcp")!;
    expect(mcp.enumerable).toBe(false);
    expect(mcp.autoAllow).toEqual([]);
    expect(mcp.rawPatterns).toEqual({
      allow: ["call:get_issue", "session:*"],
      requireApproval: ["call:delete_*"],
      deny: [],
    });
  });

  test("upstream with no matching policy grant → empty exposure (deny-by-default)", () => {
    const p = policy([{ tool: "linear", allow: ["issue:read"] }]); // no grant at all for "github"
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    const gh = report.upstreams.find((u) => u.upstream === "github")!;
    expect(gh.enumerable).toBe(true);
    expect(gh.autoAllow).toEqual([]);
    expect(gh.requiresApproval).toEqual([]);
    expect(gh.broadGrants).toEqual([]);
  });

  test("pure — same input, same output", () => {
    const p = policy([{ tool: "github", allow: ["repo:*"] }]);
    const input = {
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    };
    expect(analyzeBlastRadius(input)).toEqual(analyzeBlastRadius(input));
  });
});

describe("blast-radius: live delegations", () => {
  test("only non-expired delegations belonging to the requested agent are reported", () => {
    const p = policy([{ tool: "github", allow: ["repo:*"] }]);
    const delegations: DelegationLike[] = [
      { id: "del_1", parentAgentId: "claude-code", note: "reviewer", actions: ["repo:read"], expiresAt: 1_900_000 },
      { id: "del_2", parentAgentId: "other-agent", note: "unrelated", actions: ["repo:read"], expiresAt: 1_900_000 },
      { id: "del_3", parentAgentId: "claude-code", note: "expired", actions: ["repo:read"], expiresAt: 500_000 },
    ];
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations,
      now: 1_000_000,
    });
    expect(report.delegations).toHaveLength(1);
    expect(report.delegations[0]!.id).toBe("del_1");
    expect(report.delegations[0]!.actions).toEqual(["repo:read"]);
    expect(report.delegations[0]!.expiresInSeconds).toBe(900);
  });
});

describe("blast-radius: severity", () => {
  test("no destructive auto-allow, no broad grants → low", () => {
    const p = policy([{ tool: "github", allow: ["repo:read", "pr:create"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    expect(report.severity).toBe("low");
  });

  test("two destructive auto-allow actions → elevated", () => {
    const p = policy([{ tool: "github", allow: ["repo:delete", "pr:merge"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    expect(report.severity).toBe("elevated");
    expect(report.reasons.join(" ")).toContain("repo:delete");
  });

  test("broad grants across a destructive-heavy vocabulary → high", () => {
    const p = policy([{ tool: "github", allow: ["repo:*", "pr:*", "actions:*", "issue:*"] }]);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: p,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    expect(report.severity).toBe("high");
  });

  test("a target-scoped allow still counts as reachable exposure; a scoped deny is evadable", () => {
    const compiled = compilePolicyObject({
      agent: "claude-code", on_behalf_of: "am@team.dev",
      grants: [{
        tool: "github",
        allow: [{ action: "pr:create", targets: ["/repos/acme/*"] }, "repo:read"],
        deny: [{ action: "repo:delete", targets: ["/repos/prod-*"] }],
      }],
    });
    if (!compiled.ok) throw new Error(compiled.error);
    const report = analyzeBlastRadius({
      agent: "claude-code",
      upstreams: { github: { type: "github" } },
      policy: compiled.policy,
      delegations: NO_DELEGATIONS,
      now: 0,
    });
    const gh = report.upstreams.find((u) => u.upstream === "github")!;
    // Scoped allow: reachable via some target -> counted as exposure.
    expect(gh.autoAllow).toContain("pr:create");
    // Scoped deny: evadable via some other target -> repo:delete is NOT
    // "blocked", but it lands nowhere either (no allow) -> not auto-allowed.
    expect(gh.autoAllow).not.toContain("repo:delete");
  });
});
