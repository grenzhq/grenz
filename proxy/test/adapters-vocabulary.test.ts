import { test, expect, describe } from "bun:test";
import { actionVocabulary } from "../src/adapters/vocabulary.ts";
import { GITHUB_ACTIONS } from "../src/adapters/github.ts";
import { MCP_TRANSPORT_ACTIONS } from "../src/adapters/mcp.ts";

describe("actionVocabulary", () => {
  test("github/linear/slack are enumerable", () => {
    expect(actionVocabulary("github")).toEqual(GITHUB_ACTIONS);
    expect(actionVocabulary("linear")).not.toBeNull();
    expect(actionVocabulary("slack")).not.toBeNull();
  });

  // Linear and Slack are built on createMcpAdapter, so a real session emits the
  // MCP transport actions as well as the semantic ones. Omitting them made the
  // linter report `session:*` and `tools:list` as dead patterns — telling an
  // operator to delete the exact rules the handshake needs to connect.
  describe("MCP-based adapters include the transport actions", () => {
    for (const type of ["linear", "slack"] as const) {
      for (const action of MCP_TRANSPORT_ACTIONS) {
        test(`${type} knows ${action}`, () => {
          expect(actionVocabulary(type)).toContain(action);
        });
      }
    }
  });

  test("github is REST and carries no MCP transport actions", () => {
    const github = actionVocabulary("github") ?? [];
    for (const action of MCP_TRANSPORT_ACTIONS) expect(github).not.toContain(action);
  });

  test("semantic actions survive alongside the transport ones", () => {
    expect(actionVocabulary("linear")).toContain("issue:write");
    expect(actionVocabulary("slack")).toContain("message:send");
  });

  test("generic mcp is not enumerable (arbitrary tool names)", () => {
    expect(actionVocabulary("mcp")).toBeNull();
  });

  test("an unknown upstream type is not enumerable", () => {
    expect(actionVocabulary("something-unregistered")).toBeNull();
  });
});
