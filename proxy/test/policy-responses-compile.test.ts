import { test, expect, describe } from "bun:test";
import { compilePolicyYaml } from "../src/policy/compile.ts";

const BASE = `agent: a\non_behalf_of: x\ngrants:\n  - tool: github\n    allow: [repo:read]\n`;

describe("responses compile", () => {
  test("no responses -> empty array", () => {
    const c = compilePolicyYaml(BASE);
    expect(c.ok).toBe(true);
    if (c.ok) expect(c.policy.responses).toEqual([]);
  });

  test("a cap rule compiles with globs + defaults", () => {
    const c = compilePolicyYaml(BASE + `responses:\n  - on: [repo:read]\n    max_bytes: 1024\n`);
    expect(c.ok).toBe(true);
    if (c.ok) {
      expect(c.policy.responses).toHaveLength(1);
      const r = c.policy.responses[0]!;
      expect(r.maxBytes).toBe(1024);
      expect(r.onExceed).toBe("truncate"); // default
      expect(r.targets).toBeNull(); // omitted = any
      expect(r.on[0]!.re.test("repo:read")).toBe(true);
    }
  });

  test("targets + on_exceed: deny compile", () => {
    const c = compilePolicyYaml(
      BASE + `responses:\n  - on: ["call:*"]\n    targets: ["secret/*"]\n    max_bytes: 64\n    on_exceed: deny\n`,
    );
    expect(c.ok).toBe(true);
    if (c.ok) {
      const r = c.policy.responses[0]!;
      expect(r.onExceed).toBe("deny");
      expect(r.targets).not.toBeNull();
      expect(r.targets![0]!.re.test("secret/x")).toBe(true);
    }
  });

  test("max_bytes < 1 is rejected", () => {
    const c = compilePolicyYaml(BASE + `responses:\n  - on: [repo:read]\n    max_bytes: 0\n`);
    expect(c.ok).toBe(false);
  });

  test("empty on is rejected", () => {
    const c = compilePolicyYaml(BASE + `responses:\n  - on: []\n    max_bytes: 10\n`);
    expect(c.ok).toBe(false);
  });
});
