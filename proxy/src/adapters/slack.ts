/**
 * Slack adapter — MCP transport with a semantic tool→action map.
 *
 * Normalizes Slack MCP tool names (with or without the common `slack_` prefix)
 * into a canonical taxonomy (`message:send`, `channel:read`, …). Unknown tools
 * fall back to `call:<name>` so policies fail closed. Extend the table as the
 * Slack MCP server's tool set evolves.
 */
import { createMcpAdapter } from "./mcp.ts";

const SLACK_ACTIONS: Record<string, string> = {
  // read
  list_channels: "channel:read",
  get_channel_history: "message:read",
  get_thread_replies: "message:read",
  get_messages: "message:read",
  search_messages: "message:read",
  // write
  post_message: "message:send",
  send_message: "message:send",
  reply_to_thread: "message:send",
  update_message: "message:update",
  add_reaction: "reaction:add",
  upload_file: "file:upload",
  // directory (read-only)
  list_users: "directory:read",
  get_users: "directory:read",
  get_user_profile: "directory:read",
};

/** Every distinct canonical action the Slack tool map can produce. */
export const SLACK_ACTION_LIST: readonly string[] = Array.from(new Set(Object.values(SLACK_ACTIONS)));

function mapSlackTool(name: string): string | null {
  // Case-normalize so a `deny` cannot be evaded by tool-name casing variance.
  const lower = name.toLowerCase();
  const n = lower.startsWith("slack_") ? lower.slice("slack_".length) : lower;
  return SLACK_ACTIONS[n] ?? null;
}

export const slackAdapter = createMcpAdapter("slack", mapSlackTool);
