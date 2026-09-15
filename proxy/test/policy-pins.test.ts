import { test, expect, describe } from "bun:test";
import { compilePolicyYaml } from "../src/policy/compile.ts";

const base = `
agent: claude-code
on_behalf_of: x
grants:
  - tool: github
    allow: ["*:read", "*:write"]
`;

describe("pins schema + compile", () => {
  test("compiles a pin rule with defaults", () => {
    const r = compilePolicyYaml(
      base +
        `pins:
  - key: "^/repos/([^/]+/[^/]+)"
    on: ["*:write"]
`,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.policy.pins).toHaveLength(1);
    const p = r.policy.pins[0]!;
    expect(p.effect).toBe("require_approval"); // default
    expect(p.withinMs).toBe(3600 * 1000); // default 3600s
    expect(p.on).toHaveLength(1);
    expect(p.key.exec("/repos/acme/api/issues/1")?.[1]).toBe("acme/api");
  });

  test("honors effect: deny and within_seconds", () => {
    const r = compilePolicyYaml(
      base + `pins:\n  - key: "^/repos/([^/]+/[^/]+)"\n    on: ["*:write"]\n    effect: deny\n    within_seconds: 60\n`,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.policy.pins[0]!.effect).toBe("deny");
    expect(r.policy.pins[0]!.withinMs).toBe(60 * 1000);
  });

  test("fail-loud: a key regex with no capture group is rejected at compile", () => {
    const r = compilePolicyYaml(base + `pins:\n  - key: "^/repos/[^/]+/[^/]+"\n    on: ["*:write"]\n`);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/capture group/i);
  });

  test("fail-loud: a malformed key regex is rejected at compile", () => {
    const r = compilePolicyYaml(base + `pins:\n  - key: "^/repos/([("\n    on: ["*:write"]\n`);
    expect(r.ok).toBe(false);
  });

  test("no pins -> empty array", () => {
    const r = compilePolicyYaml(base);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.policy.pins).toEqual([]);
  });
});

describe("pin key case-insensitivity (the escalation-site rule)", () => {
  // The pin key is a raw regex over the request target, and pins are an
  // ESCALATION site: failing to match makes the rule INERT, which is fail-OPEN.
  // A mis-cased path prefix used to do exactly that — `/REPOS/acme/api` did not
  // match `^/repos/...`, so the session was silently unpinned and free to roam.
  // Scoped target globs got the same treatment for the same reason.
  function pinsOf(yaml: string) {
    const r = compilePolicyYaml(`agent: a\non_behalf_of: x\n${yaml}`);
    if (!r.ok) throw new Error(r.error);
    return r.policy.pins;
  }
  const PINS = pinsOf(`
pins:
  - key: "^/repos/([^/]+/[^/]+)"
    on: ["*:write"]
`);

  const CASES: readonly { name: string; target: string; unit: string | null }[] = [
    { name: "exact case matches", target: "/repos/acme/api/x", unit: "acme/api" },
    { name: "upper-cased prefix still matches (was: rule went inert)", target: "/REPOS/acme/api/x", unit: "acme/api" },
    { name: "mixed-case prefix still matches", target: "/RePoS/acme/api/x", unit: "acme/api" },
    { name: "a genuinely different path does not match", target: "/orgs/acme/api", unit: null },
  ];
  for (const c of CASES) {
    test(c.name, () => {
      expect(PINS[0]!.key.exec(c.target)?.[1] ?? null).toBe(c.unit);
    });
  }

  test("the extracted UNIT keeps its own case (comparison stays exact)", () => {
    // Matching is case-insensitive so the rule cannot be made inert; the unit
    // itself is compared verbatim, so a case-shifted unit escalates rather than
    // being silently merged with the pinned one. Friction, never a bypass.
    expect(PINS[0]!.key.exec("/repos/ACME/API/x")?.[1]).toBe("ACME/API");
  });

  test("a key with its own inline flags still compiles", () => {
    const pins = pinsOf(`
pins:
  - key: "^/x/([a-z]+)"
    on: ["*:write"]
`);
    expect(pins[0]!.key.flags).toContain("i");
  });
});
