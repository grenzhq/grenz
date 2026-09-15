import { test, expect, describe } from "bun:test";
import { slackAdapter, SLACK_ACTION_LIST } from "../src/adapters/slack.ts";
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
  const out = slackAdapter.map(toolCall(name));
  if (isUnsupported(out)) throw new Error(out.unsupported);
  return out.actions[0]!;
}

describe("slack adapter", () => {
  const cases: Array<[tool: string, action: string]> = [
    ["list_channels", "channel:read"],
    ["get_channel_history", "message:read"],
    ["get_thread_replies", "message:read"],
    ["post_message", "message:send"],
    ["reply_to_thread", "message:send"],
    ["add_reaction", "reaction:add"],
    ["upload_file", "file:upload"],
    ["list_users", "directory:read"],
    // the common `slack_` prefix is stripped before mapping
    ["slack_post_message", "message:send"],
    ["slack_list_channels", "channel:read"],
  ];
  for (const [tool, action] of cases) {
    test(`${tool} -> ${action}`, () => expect(actionOf(tool)).toBe(action));
  }

  test("unknown tool falls back to call:<name> (deny-by-default)", () => {
    expect(actionOf("delete_workspace")).toBe("call:delete_workspace");
  });

  test("adapter type is slack", () => {
    expect(slackAdapter.type).toBe("slack");
  });
});

describe("slack action vocabulary", () => {
  test("contains the known read/write actions", () => {
    expect(SLACK_ACTION_LIST).toEqual(expect.arrayContaining([
      "message:send", "message:read", "channel:read", "file:upload",
    ]));
  });

  test("has no duplicates", () => {
    expect(new Set(SLACK_ACTION_LIST).size).toBe(SLACK_ACTION_LIST.length);
  });
});
