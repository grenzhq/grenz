import { test, expect, describe } from "bun:test";
import { lintDecoys } from "../src/policy/lint.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";

function policy(yaml: string) {
  const r = compilePolicyYaml(yaml);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

const upstreams = {
  github: { type: "github", decoy: false },
  honeypot: { type: "mcp", decoy: true },
} as const;

describe("lintDecoys", () => {
  test("a grant naming a decoy upstream is flagged", () => {
    const p = policy(`agent: a\non_behalf_of: x\ngrants:\n  - tool: honeypot\n    allow: ["*"]`);
    const findings = lintDecoys(p, upstreams);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.detail).toContain("decoy");
  });

  test("a grant naming a real upstream is not flagged", () => {
    const p = policy(`agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]`);
    expect(lintDecoys(p, upstreams)).toHaveLength(0);
  });
});
