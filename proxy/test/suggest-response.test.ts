import { test, expect, describe } from "bun:test";
import { stripCodeFence, validateSuggestion } from "../src/suggest/response.ts";

const VALID_POLICY = "agent: claude-code\non_behalf_of: you@example.com\ngrants:\n  - tool: github\n    allow: [repo:read]\n";

describe("stripCodeFence", () => {
  test("unwraps a ```yaml fenced block", () => {
    expect(stripCodeFence("```yaml\n" + VALID_POLICY + "```")).toBe(VALID_POLICY.trim());
  });

  test("unwraps a plain ``` fenced block (no language tag)", () => {
    expect(stripCodeFence("```\n" + VALID_POLICY + "```")).toBe(VALID_POLICY.trim());
  });

  test("passes an unfenced response through (trimmed)", () => {
    expect(stripCodeFence(`  ${VALID_POLICY}  `)).toBe(VALID_POLICY.trim());
  });
});

describe("validateSuggestion", () => {
  test("valid YAML compiles and is accepted", () => {
    const r = validateSuggestion(VALID_POLICY);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.yaml).toBe(VALID_POLICY.trim());
  });

  test("a fenced valid response is accepted", () => {
    const r = validateSuggestion("```yaml\n" + VALID_POLICY + "```");
    expect(r.ok).toBe(true);
  });

  test("invalid YAML is rejected (nothing would be written)", () => {
    const r = validateSuggestion("agent: : :\n  - broken");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("malformed policy");
  });

  test("a response failing schema validation (unknown key) is rejected", () => {
    const r = validateSuggestion("agent: a\non_behalf_of: b\ngrants: []\nsurprise: true\n");
    expect(r.ok).toBe(false);
  });
});
