import { test, expect, describe } from "bun:test";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { evaluate } from "../src/policy/evaluate.ts";
import type { Decision, ReasonCode } from "../src/policy/types.ts";

/**
 * Table-driven coverage for `EvalInput.unresolved`.
 *
 * An unresolved target is a target that EXISTS but could not be proven —
 * `curl $URL`. The rule is one line and this table is every branch of it:
 * unprovable never matches a target GLOB, in either direction, while rules that
 * do not look at targets behave exactly as they always do.
 */
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

interface Row {
  readonly name: string;
  readonly grant: string;
  readonly action: string;
  readonly target: string;
  readonly unresolved: boolean;
  readonly decision: Decision;
  readonly reason: ReasonCode;
}

const SCOPED_ALLOW = `
  - tool: bash
    allow:
      - action: "exec:curl"
        targets: ["curl https://api.internal/*"]
`;

const UNSCOPED_DENY = `
  - tool: bash
    allow:
      - action: "exec:curl"
        targets: ["curl https://api.internal/*"]
    deny:
      - exec:curl
`;

const SCOPED_DENY = `
  - tool: bash
    allow:
      - exec:curl
    deny:
      - action: "exec:curl"
        targets: ["curl * evil.com *"]
`;

const UNSCOPED_ALLOW = `
  - tool: bash
    allow:
      - exec:curl
`;

const OPTED_IN = `
  - tool: bash
    allow:
      - action: "exec:curl"
        targets: ["curl https://api.internal/*"]
        on_unresolved: approve
`;

const SCOPED_APPROVAL = `
  - tool: bash
    allow:
      - exec:ls
    require_approval:
      - action: "exec:curl"
        targets: ["curl *"]
`;

const UNSCOPED_APPROVAL = `
  - tool: bash
    allow:
      - exec:ls
    require_approval:
      - exec:curl
`;

const TABLE: Row[] = [
  // --- resolved targets behave exactly as before -----------------------------
  {
    name: "resolved target matching a scoped allow",
    grant: SCOPED_ALLOW,
    action: "exec:curl",
    target: "curl https://api.internal/v1",
    unresolved: false,
    decision: "allow",
    reason: "explicit_allow",
  },
  {
    name: "resolved target missing every allow",
    grant: SCOPED_ALLOW,
    action: "exec:curl",
    target: "curl https://evil.example",
    unresolved: false,
    decision: "deny",
    reason: "no_matching_allow",
  },

  // --- unprovable never matches a target GLOB --------------------------------
  {
    name: "unresolved target CANNOT satisfy a scoped allow",
    grant: SCOPED_ALLOW,
    action: "exec:curl",
    // The string would match `curl https://api.internal/*` if it were compared,
    // which is exactly why the flag has to short-circuit before the comparison.
    target: "curl https://api.internal/$PATH",
    unresolved: true,
    decision: "deny",
    reason: "unresolved_target",
  },
  {
    name: "unresolved target CANNOT trip a scoped deny either",
    grant: SCOPED_DENY,
    action: "exec:curl",
    target: "curl $URL evil.com $X",
    unresolved: true,
    // Falls through to the unscoped allow, which never looked at targets.
    decision: "allow",
    reason: "explicit_allow",
  },
  {
    name: "unresolved target CANNOT match a scoped require_approval",
    grant: SCOPED_APPROVAL,
    action: "exec:curl",
    target: "curl $URL",
    unresolved: true,
    decision: "deny",
    reason: "unresolved_target",
  },

  // --- rules that ignore targets are unaffected ------------------------------
  {
    name: "an UNSCOPED deny is absolute and fires on an unresolved target",
    grant: UNSCOPED_DENY,
    action: "exec:curl",
    target: "curl $URL",
    unresolved: true,
    // The whole point of routing this to the engine: the deny owns the outcome
    // and the log records it, instead of `exec_undecidable` taking the credit.
    decision: "deny",
    reason: "explicit_deny",
  },
  {
    name: "an UNSCOPED allow grants an unresolved target — it never read argv",
    grant: UNSCOPED_ALLOW,
    action: "exec:curl",
    target: "curl $URL",
    unresolved: true,
    decision: "allow",
    reason: "explicit_allow",
  },
  {
    name: "an UNSCOPED require_approval fires on an unresolved target",
    grant: UNSCOPED_APPROVAL,
    action: "exec:curl",
    target: "curl $URL",
    unresolved: true,
    decision: "require_approval",
    reason: "approval_required",
  },

  // --- the opt-in ------------------------------------------------------------
  {
    name: "on_unresolved: approve asks instead of blocking",
    grant: OPTED_IN,
    action: "exec:curl",
    target: "curl $URL",
    unresolved: true,
    decision: "require_approval",
    reason: "unresolved_approval",
  },
  {
    name: "on_unresolved: approve does NOT widen a resolved target",
    grant: OPTED_IN,
    action: "exec:curl",
    target: "curl https://evil.example",
    unresolved: false,
    decision: "deny",
    reason: "no_matching_allow",
  },
  {
    name: "on_unresolved: approve only covers its own action",
    grant: OPTED_IN,
    action: "exec:rm",
    target: "rm $F",
    unresolved: true,
    decision: "deny",
    reason: "unresolved_target",
  },

  // --- deny-by-default with no grant at all ----------------------------------
  {
    name: "no grant for the tool still wins over everything",
    grant: `
  - tool: github
    allow: [repo:read]
`,
    action: "exec:curl",
    target: "curl $URL",
    unresolved: true,
    decision: "deny",
    reason: "no_grant_for_tool",
  },
];

describe("engine — unresolved targets", () => {
  for (const row of TABLE) {
    test(row.name, () => {
      const policy = compile(HEAD + row.grant);
      const r = evaluate(policy, {
        tool: "bash",
        action: row.action,
        target: row.target,
        unresolved: row.unresolved,
      });
      expect([r.decision, r.reason]).toEqual([row.decision, row.reason]);
    });
  }

  test("omitting the flag is identical to passing false", () => {
    const policy = compile(HEAD + SCOPED_ALLOW);
    const input = { tool: "bash", action: "exec:curl", target: "curl https://api.internal/v1" };
    expect(evaluate(policy, input)).toEqual(evaluate(policy, { ...input, unresolved: false }));
  });

  test("on_unresolved is rejected on a deny clause — a malformed policy denies", () => {
    // `.strict()` is the security property: an inert key on the wrong clause
    // would read as protection that is not there.
    const r = compilePolicyYaml(`${HEAD}
  - tool: bash
    allow: [exec:ls]
    deny:
      - action: "exec:curl"
        on_unresolved: approve
`);
    expect(r.ok).toBe(false);
  });

  test("default is deny, so an untouched policy behaves exactly as it shipped", () => {
    const policy = compile(HEAD + SCOPED_ALLOW);
    const grant = policy.grants.get("bash")!;
    expect(grant.allow.every((r) => r.onUnresolved === "deny")).toBe(true);
  });
});
