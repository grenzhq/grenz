import { test, expect, describe } from "bun:test";
import { linearAdapter, LINEAR_ACTION_LIST } from "../src/adapters/linear.ts";
import { isUnsupported, type AdapterRequest } from "../src/adapters/types.ts";

function toolCall(name: string): AdapterRequest {
  return {
    method: "POST",
    path: "/",
    query: "",
    body: new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name } })),
    contentType: "application/json",
  };
}

function actionOf(name: string): string {
  const out = linearAdapter.map(toolCall(name));
  if (isUnsupported(out)) throw new Error(out.unsupported);
  return out.actions[0]!;
}

describe("linear adapter", () => {
  // Real Linear MCP tool names (Linear uses save_* upserts + delete_* on
  // comments/attachments/status updates).
  const cases: Array<[tool: string, action: string]> = [
    ["list_issues", "issue:read"],
    ["get_issue", "issue:read"],
    ["save_issue", "issue:write"],
    ["list_comments", "comment:read"],
    ["save_comment", "comment:write"],
    ["delete_comment", "comment:delete"],
    ["list_projects", "project:read"],
    ["save_project", "project:write"],
    ["search_documentation", "doc:read"],
    ["save_document", "doc:write"],
    ["delete_attachment", "attachment:delete"],
    ["create_attachment", "attachment:write"],
    ["delete_status_update", "status:delete"],
    ["list_teams", "directory:read"],
    ["get_user", "directory:read"],
    ["create_issue_label", "directory:write"],
  ];
  for (const [tool, action] of cases) {
    test(`${tool} -> ${action}`, () => expect(actionOf(tool)).toBe(action));
  }

  test("tool-name casing cannot evade the mapping (deny robustness)", () => {
    expect(actionOf("Delete_Comment")).toBe("comment:delete");
    expect(actionOf("SAVE_ISSUE")).toBe("issue:write");
  });

  test("unknown tool falls back to call:<name> (deny-by-default)", () => {
    expect(actionOf("frobnicate_widget")).toBe("call:frobnicate_widget");
    // Tools that do NOT exist on the real server must not silently map.
    expect(actionOf("delete_issue")).toBe("call:delete_issue");
  });

  test("adapter type is linear", () => {
    expect(linearAdapter.type).toBe("linear");
  });

  test("non-tools/call MCP methods still map (handshake works)", () => {
    const out = linearAdapter.map({
      method: "POST",
      path: "/",
      query: "",
      body: new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })),
      contentType: null,
    });
    if (isUnsupported(out)) throw new Error("unexpected");
    expect(out.actions).toEqual(["tools:list"]);
  });
});

describe("linear action vocabulary", () => {
  test("contains the known read/write/delete actions", () => {
    expect(LINEAR_ACTION_LIST).toEqual(expect.arrayContaining([
      "issue:read", "issue:write", "comment:delete", "project:write",
    ]));
  });

  test("has no duplicates", () => {
    expect(new Set(LINEAR_ACTION_LIST).size).toBe(LINEAR_ACTION_LIST.length);
  });
});
