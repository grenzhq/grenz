import { test, expect, describe } from "bun:test";
import { classifyAction, vocabulary, CLASSES, type ActionClass } from "../src/adapters/classify.ts";

describe("action classification", () => {
  const cases: Array<[string, string, ActionClass]> = [
    // github — the launch wedge
    ["github", "repo:read", "safe"],
    ["github", "pr:create", "safe"],
    ["github", "issue:create", "safe"],
    ["github", "api:read", "safe"],
    ["github", "pr:comment", "sensitive"],
    ["github", "issue:update", "sensitive"],
    ["github", "repo:write", "sensitive"],
    ["github", "pr:merge", "destructive"],
    ["github", "repo:delete", "destructive"],
    ["github", "actions:write", "destructive"],
    ["github", "api:write", "destructive"],
    // linear
    ["linear", "issue:read", "safe"],
    ["linear", "issue:write", "sensitive"],
    ["linear", "comment:delete", "destructive"],
    // slack
    ["slack", "message:read", "safe"],
    ["slack", "message:send", "sensitive"],
    ["slack", "file:upload", "exfil"],
  ];

  for (const [type, action, expected] of cases) {
    test(`${type} ${action} → ${expected}`, () => {
      expect(classifyAction(type, action)).toBe(expected);
    });
  }

  test("an unknown action fails closed → destructive", () => {
    expect(classifyAction("github", "totally:madeup")).toBe("destructive");
    expect(classifyAction("slack", "call:evil_tool")).toBe("destructive");
  });

  test("an unknown upstream type fails closed → destructive", () => {
    expect(classifyAction("mystery", "anything:goes")).toBe("destructive");
  });

  test("vocabulary lists the known actions; generic mcp has none", () => {
    expect(vocabulary("github")).toContain("pr:merge");
    expect(vocabulary("github").length).toBeGreaterThan(10);
    expect(vocabulary("mcp")).toEqual([]);
  });

  test("every classified action is one of the four classes", () => {
    const valid = new Set(["safe", "sensitive", "destructive", "exfil"]);
    for (const [type, map] of Object.entries(CLASSES)) {
      for (const [action, cls] of Object.entries(map)) {
        expect(valid.has(cls)).toBe(true);
        expect(action).toMatch(/^[a-z]+:[a-z*]+$/); // canonical tool:verb shape
      }
    }
  });
});
