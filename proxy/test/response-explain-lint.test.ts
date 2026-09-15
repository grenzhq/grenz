import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { buildExplain, type ExplainInputs } from "../src/explain/report.ts";
import { renderExplainLines } from "../src/cli/explain.ts";
import { lintResponses } from "../src/policy/lint.ts";

const UPSTREAMS = { github: { type: "github" } } as const;

const YAML = `
agent: a
on_behalf_of: x
grants:
  - tool: github
    allow: ["*:read", "*:write"]
responses:
  - on: ["repo:read"]
    max_bytes: 4096
`;

function compile(yaml: string): CompiledPolicy {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

describe("lintResponses", () => {
  test("clean cap rule -> no findings", () => {
    expect(lintResponses(compile(YAML), UPSTREAMS)).toEqual([]);
  });

  test("a dead `on` glob matching no known action -> a finding", () => {
    const p = compile(YAML.replace(`on: ["repo:read"]`, `on: ["nonsense:frobnicate"]`));
    const findings = lintResponses(p, UPSTREAMS);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.pattern).toBe("nonsense:frobnicate");
    expect(findings[0]!.ruleIndex).toBe(0);
  });
});

describe("explain responses line", () => {
  const policy = compile(YAML);
  function inputs(over: Partial<ExplainInputs>): ExplainInputs {
    return {
      policy,
      tool: "github",
      action: "repo:read",
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

  test("renders a stateless responses: line for a capped action", () => {
    const report = buildExplain(inputs({}));
    expect(report.responseCap).toEqual({ maxBytes: 4096, onExceed: "truncate" });
    const lines = renderExplainLines(report, { agentId: "a", tool: "github", action: "repo:read", target: null, policy });
    const joined = lines.join("\n");
    expect(joined).toContain("responses:");
    expect(joined).toContain("4096B");
  });

  test("no responses: line for an uncapped action", () => {
    const report = buildExplain(inputs({ action: "repo:write" }));
    expect(report.responseCap).toBeNull();
    const lines = renderExplainLines(report, { agentId: "a", tool: "github", action: "repo:write", target: null, policy });
    expect(lines.join("\n")).not.toContain("responses:");
  });
});
