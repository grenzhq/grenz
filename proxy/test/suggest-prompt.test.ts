import { test, expect, describe } from "bun:test";
import { buildPrompt, type PromptInput } from "../src/suggest/prompt.ts";

const BASE_INPUT: PromptInput = {
  intent: "let the linear agent triage tickets but never delete",
  currentPolicyYaml: "agent: claude-code\non_behalf_of: you@example.com\ngrants: []\n",
  vocabularyByUpstream: {
    github: { type: "github", actions: ["repo:read", "pr:merge", "repo:delete"] },
    mcp: { type: "mcp", actions: null },
  },
};

describe("buildPrompt", () => {
  test("includes the current policy YAML verbatim", () => {
    const prompt = buildPrompt(BASE_INPUT);
    expect(prompt).toContain(BASE_INPUT.currentPolicyYaml);
  });

  test("includes an enumerable upstream's full action list", () => {
    const prompt = buildPrompt(BASE_INPUT);
    expect(prompt).toContain("repo:read");
    expect(prompt).toContain("pr:merge");
    expect(prompt).toContain("repo:delete");
  });

  test("describes a non-enumerable upstream without fabricating an action list", () => {
    const prompt = buildPrompt(BASE_INPUT);
    expect(prompt).toContain("mcp");
    expect(prompt).toContain("not enumerable");
  });

  test("includes the intent string", () => {
    const prompt = buildPrompt(BASE_INPUT);
    expect(prompt).toContain(BASE_INPUT.intent);
  });

  test("pure — same input, same output", () => {
    expect(buildPrompt(BASE_INPUT)).toBe(buildPrompt(BASE_INPUT));
  });
});
