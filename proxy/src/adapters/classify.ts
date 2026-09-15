/**
 * Action risk classification — Grenz's per-adapter knowledge of which actions
 * are routine, notable, irreversible, or exfil-shaped. This is the single lever
 * that lets a user express a *preference* ("normal" / "strict") instead of
 * enumerating actions: the risk of each action ships here, in the product, not
 * in the user's policy.
 *
 * Pure data + pure functions. Unknown actions classify as `destructive` — an
 * unrecognized action is never silently treated as safe (fail closed).
 */

export type ActionClass = "safe" | "sensitive" | "destructive" | "exfil";
//  safe        — reversible, routine (reads, opening a PR/issue)
//  sensitive   — reversible but notable (edits, comments, file writes)
//  destructive — irreversible or high-blast (merge, delete, CI writes)
//  exfil       — a call that can move data/secrets out at scale

const GITHUB: Readonly<Record<string, ActionClass>> = {
  "repo:read": "safe",
  "pr:read": "safe",
  "issue:read": "safe",
  "user:read": "safe",
  "org:read": "safe",
  "search:read": "safe",
  "actions:read": "safe",
  "api:read": "safe",
  "pr:create": "safe",
  "issue:create": "safe",
  "pr:comment": "sensitive",
  "issue:update": "sensitive",
  "pr:update": "sensitive",
  "repo:write": "sensitive", // contents-API file writes; git push isn't proxied
  "pr:merge": "destructive",
  "repo:delete": "destructive",
  "actions:write": "destructive", // CI config = lateral movement
  "api:write": "destructive", // coarse fallback for any unmapped write
};

const LINEAR: Readonly<Record<string, ActionClass>> = {
  "issue:read": "safe",
  "comment:read": "safe",
  "project:read": "safe",
  "milestone:read": "safe",
  "status:read": "safe",
  "attachment:read": "safe",
  "doc:read": "safe",
  "diff:read": "safe",
  "directory:read": "safe",
  "release:read": "safe",
  "issue:write": "sensitive",
  "comment:write": "sensitive",
  "doc:write": "sensitive",
  "project:write": "sensitive",
  "milestone:write": "sensitive",
  "status:write": "sensitive",
  "attachment:write": "sensitive",
  "directory:write": "sensitive",
  "release:write": "sensitive",
  "comment:delete": "destructive",
  "status:delete": "destructive",
  "attachment:delete": "destructive",
};

const SLACK: Readonly<Record<string, ActionClass>> = {
  "message:read": "safe",
  "channel:read": "safe",
  "directory:read": "safe",
  "reaction:add": "sensitive",
  "message:update": "sensitive",
  "message:send": "sensitive",
  "file:upload": "exfil", // uploading files out is the exfil channel
};

export const CLASSES: Readonly<Record<string, Readonly<Record<string, ActionClass>>>> = {
  github: GITHUB,
  linear: LINEAR,
  slack: SLACK,
};

/** MCP-transport adapters (slack, linear) fall back to `call:<tool>` for tools
 *  outside their known map. Those unknown tools ask, never silently allow. */
export const TAIL_TYPES = new Set(["slack", "linear"]);

/** Classify one action for an upstream type. Unknown → destructive (fail closed). */
export function classifyAction(upstreamType: string, action: string): ActionClass {
  return CLASSES[upstreamType]?.[action] ?? "destructive";
}

/** The known action vocabulary for an upstream type (empty for generic `mcp`). */
export function vocabulary(upstreamType: string): readonly string[] {
  return Object.keys(CLASSES[upstreamType] ?? {});
}
