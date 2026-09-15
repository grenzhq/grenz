import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { buildExplain, type ExplainInputs } from "../src/explain/report.ts";
import { renderExplainLines } from "../src/cli/explain.ts";
import { lintPins } from "../src/policy/lint.ts";

const UPSTREAMS = { github: { type: "github" } } as const;

const YAML = `
agent: a
on_behalf_of: x
grants:
  - tool: github
    allow: ["*:read", "*:write", "issue:update"]
pins:
  - key: "^/repos/([^/]+/[^/]+)"
    on: ["issue:update"]
`;

function compile(yaml: string): CompiledPolicy {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

describe("lintPins", () => {
  test("clean pin rule -> no findings", () => {
    expect(lintPins(compile(YAML), UPSTREAMS)).toEqual([]);
  });

  test("a dead `on` glob matching no known action -> a finding", () => {
    const p = compile(YAML.replace(`on: ["issue:update"]`, `on: ["nonsense:frobnicate"]`));
    const findings = lintPins(p, UPSTREAMS);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.pattern).toBe("nonsense:frobnicate");
  });
});

describe("explain pin line", () => {
  const policy = compile(YAML);
  function inputs(over: Partial<ExplainInputs>): ExplainInputs {
    return {
      policy,
      tool: "github",
      action: "issue:update",
      target: null,
      agentId: "a",
      revoked: null,
      activeGrants: [],
      spentAgent: 0,
      spentUpstream: 0,
      riskLevel: null,
      scheduleOpen: null,
      firstUseSeen: null,
      approvals: { ttlSeconds: 300, rememberSeconds: 0 },
      ...over,
    };
  }

  test("renders a stateless pin: line for a constrained action", () => {
    const report = buildExplain(inputs({}));
    const lines = renderExplainLines(report, { agentId: "a", tool: "github", action: "issue:update", target: null, policy });
    expect(lines.join("\n")).toContain("pin:");
  });

  test("no pin: line for an action outside every rule's `on`", () => {
    const report = buildExplain(inputs({ action: "repo:read" }));
    const lines = renderExplainLines(report, { agentId: "a", tool: "github", action: "repo:read", target: null, policy });
    expect(lines.join("\n")).not.toContain("pin:");
  });
});
