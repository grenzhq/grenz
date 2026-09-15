import { test, expect, describe } from "bun:test";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { parsePolicyTests, runPolicyTests } from "../src/policy/test-runner.ts";

const POLICY: CompiledPolicy = (() => {
  const r = compilePolicyYaml(`
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow:
      - repo:read
      - action: "pr:*"
        targets: ["/repos/acme/*"]
    deny: [repo:delete]
    require_approval: [issue:update]
`);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
})();

describe("parsePolicyTests", () => {
  test("valid file parses into cases", () => {
    const r = parsePolicyTests(`tests:\n  - tool: github\n    action: repo:read\n    expect: allow`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.cases.length).toBe(1);
      expect(r.cases[0]!.tool).toBe("github");
      expect(r.cases[0]!.expect).toBe("allow");
    }
  });

  test("empty tests list rejected", () => {
    expect(parsePolicyTests(`tests: []`).ok).toBe(false);
  });

  test("missing tests key rejected", () => {
    expect(parsePolicyTests(`other: 1`).ok).toBe(false);
  });

  test("unknown key in a case rejected (strict)", () => {
    expect(parsePolicyTests(`tests:\n  - tool: github\n    action: x\n    expect: allow\n    surprise: 1`).ok).toBe(false);
  });

  test("bad expect value rejected", () => {
    expect(parsePolicyTests(`tests:\n  - tool: github\n    action: x\n    expect: maybe`).ok).toBe(false);
  });

  test("invalid YAML -> error", () => {
    expect(parsePolicyTests(`tests: : :`).ok).toBe(false);
  });
});

describe("runPolicyTests", () => {
  const run = (yaml: string) => {
    const p = parsePolicyTests(yaml);
    if (!p.ok) throw new Error(p.error);
    return runPolicyTests(POLICY, p.cases);
  };

  test("passing decision assertions", () => {
    const res = run(`tests:
  - tool: github
    action: repo:read
    expect: allow
  - tool: github
    action: repo:delete
    expect: deny
  - tool: github
    action: issue:update
    expect: require_approval`);
    expect(res.passed).toBe(3);
    expect(res.failed).toBe(0);
    expect(res.rows.every((r) => r.pass)).toBe(true);
  });

  test("a wrong expectation fails and reports got/want", () => {
    const res = run(`tests:\n  - tool: github\n    action: repo:delete\n    expect: allow`);
    expect(res.failed).toBe(1);
    expect(res.rows[0]!.pass).toBe(false);
    expect(res.rows[0]!.got.decision).toBe("deny");
    expect(res.rows[0]!.want.decision).toBe("allow");
  });

  test("reason pin: matches decision but wrong reason -> fail", () => {
    const res = run(`tests:\n  - tool: github\n    action: totally:unknown\n    expect: deny\n    reason: explicit_deny`);
    expect(res.rows[0]!.pass).toBe(false); // real reason is no_matching_allow
    expect(res.rows[0]!.got.reason).toBe("no_matching_allow");
  });

  test("reason pin: correct reason passes", () => {
    const res = run(`tests:\n  - tool: github\n    action: repo:delete\n    expect: deny\n    reason: explicit_deny`);
    expect(res.rows[0]!.pass).toBe(true);
  });

  test("omitted target = reachability: scoped allow passes without a target", () => {
    const res = run(`tests:\n  - tool: github\n    action: pr:create\n    expect: allow`);
    expect(res.rows[0]!.pass).toBe(true);
  });

  test("with a target, scope is enforced", () => {
    const res = run(`tests:
  - name: acme allowed
    tool: github
    action: pr:create
    target: /repos/acme/x/pulls
    expect: allow
  - name: other denied
    tool: github
    action: pr:create
    target: /repos/other/x
    expect: deny`);
    expect(res.passed).toBe(2);
    expect(res.rows[0]!.name).toBe("acme allowed");
  });

  test("default row name falls back to tool:action", () => {
    const res = run(`tests:\n  - tool: github\n    action: repo:read\n    expect: allow`);
    expect(res.rows[0]!.name).toBe("github:repo:read");
  });
});
