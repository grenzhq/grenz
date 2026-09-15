import { test, expect, describe } from "bun:test";
import { globMatch } from "../src/policy/glob.ts";

describe("glob", () => {
  const cases: Array<[pattern: string, value: string, expected: boolean]> = [
    ["repo:read", "repo:read", true],
    ["repo:read", "repo:write", false],
    ["pr:*", "pr:merge", true],
    ["pr:*", "pr:", true],
    ["pr:*", "prx", false],
    ["actions:*", "actions:read", true],
    ["actions:*", "actions:write", true],
    ["*", "anything:at:all", true],
    ["*", "", true],
    ["call:list_*", "call:list_issues", true],
    ["call:list_*", "call:get_issue", false],
    ["call:*_admin", "call:delete_admin", true],
    ["call:*_admin", "call:delete_issue", false],
    ["issue:?ead", "issue:read", true],
    ["issue:?ead", "issue:reead", false],
    // regex metacharacters in the value must be treated literally
    ["a.b", "a.b", true],
    ["a.b", "axb", false],
    ["seg+ment", "seg+ment", true],
  ];

  for (const [pattern, value, expected] of cases) {
    test(`"${pattern}" ~ "${value}" => ${expected}`, () => {
      expect(globMatch(pattern, value)).toBe(expected);
    });
  }
});
