/**
 * Linear adapter — MCP transport with a semantic tool→action map.
 *
 * The table below mirrors the ACTUAL Linear MCP server toolset (Linear uses
 * `save_*` upserts, not separate create/update, and exposes `delete_comment` /
 * `delete_attachment` / `delete_status_update`). Keeping it faithful matters:
 * a policy `deny: [comment:delete]` must map to a tool that really exists, or it
 * gives false assurance. Unknown tools fall back to `call:<name>` so a
 * deny-by-default policy still blocks them.
 *
 * Actions are `resource:access` where access ∈ {read, write, delete}. Note that
 * `save_*` is an upsert, so it maps to `:write` (covers create AND update) —
 * gate it with `require_approval` if you want a human in the loop.
 */
import { createMcpAdapter } from "./mcp.ts";

const LINEAR_ACTIONS: Record<string, string> = {
  // issues
  get_issue: "issue:read",
  list_issues: "issue:read",
  save_issue: "issue:write",
  // comments
  list_comments: "comment:read",
  save_comment: "comment:write",
  delete_comment: "comment:delete",
  // projects
  get_project: "project:read",
  list_projects: "project:read",
  save_project: "project:write",
  // documents
  get_document: "doc:read",
  list_documents: "doc:read",
  search_documentation: "doc:read",
  save_document: "doc:write",
  // milestones
  get_milestone: "milestone:read",
  list_milestones: "milestone:read",
  save_milestone: "milestone:write",
  // status updates
  get_status_updates: "status:read",
  save_status_update: "status:write",
  delete_status_update: "status:delete",
  // attachments
  get_attachment: "attachment:read",
  create_attachment: "attachment:write",
  create_attachment_from_upload: "attachment:write",
  prepare_attachment_upload: "attachment:write",
  delete_attachment: "attachment:delete",
  // diffs / releases (read-heavy)
  get_diff: "diff:read",
  get_diff_threads: "diff:read",
  get_release: "release:read",
  list_releases: "release:read",
  get_release_note: "release:read",
  list_release_notes: "release:read",
  list_release_pipelines: "release:read",
  save_release: "release:write",
  save_release_note: "release:write",
  // reference / directory data (read-only lookups + label creation)
  get_team: "directory:read",
  list_teams: "directory:read",
  get_user: "directory:read",
  list_users: "directory:read",
  list_cycles: "directory:read",
  list_issue_labels: "directory:read",
  list_issue_statuses: "directory:read",
  get_issue_status: "directory:read",
  list_project_labels: "directory:read",
  list_agent_skills: "directory:read",
  get_agent_skill: "directory:read",
  create_issue_label: "directory:write",
};

/** Every distinct canonical action the Linear tool map can produce. */
export const LINEAR_ACTION_LIST: readonly string[] = Array.from(new Set(Object.values(LINEAR_ACTIONS)));

function mapLinearTool(name: string): string | null {
  // Case-normalize so a `deny` cannot be evaded by tool-name casing variance.
  return LINEAR_ACTIONS[name.toLowerCase()] ?? null;
}

export const linearAdapter = createMcpAdapter("linear", mapLinearTool);
