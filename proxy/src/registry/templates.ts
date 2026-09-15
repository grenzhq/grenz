/**
 * Bundled policy template registry.
 *
 * Templates are curated, risk-tiered policy fragments that snap into a local
 * policy with `grenz add <tool> --template <name>`. They are the seed of the
 * template registry / "policy graph": ship safe defaults per tool so a new user
 * starts from battle-tested rules instead of a blank file.
 *
 * These are bundled (compiled into the binary). The lookup is behind
 * `templateRegistry` so a remote registry backend can slot in later without
 * touching call sites.
 */

export type UpstreamType = "github" | "mcp" | "linear" | "slack";
export type RiskTier = "low" | "medium" | "high";

export interface TemplateGrant {
  readonly allow?: readonly string[];
  readonly deny?: readonly string[];
  readonly require_approval?: readonly string[];
}

export interface PolicyTemplate {
  readonly name: string; // e.g. "safe-defaults"
  readonly type: UpstreamType;
  readonly description: string;
  readonly riskTier: RiskTier;
  /** Default upstream base_url suggested when adding this template. */
  readonly baseUrl: string;
  readonly grant: TemplateGrant;
}

const TEMPLATES: readonly PolicyTemplate[] = [
  {
    name: "safe-defaults",
    type: "github",
    description: "Read freely, open/comment on PRs & issues; never merge, delete, or touch CI.",
    riskTier: "low",
    baseUrl: "https://api.github.com",
    grant: {
      allow: [
        "repo:read",
        "pr:read",
        "pr:create",
        "pr:comment",
        "pr:update",
        "issue:read",
        "issue:create",
        "issue:update",
        "user:read",
        "org:read",
        "search:read",
      ],
      deny: ["pr:merge", "repo:delete", "repo:write", "actions:*"],
    },
  },
  {
    name: "read-only",
    type: "github",
    description: "Look but never touch — good for research/triage agents.",
    riskTier: "low",
    baseUrl: "https://api.github.com",
    grant: {
      allow: ["repo:read", "pr:read", "issue:read", "user:read", "org:read", "search:read"],
    },
  },
  {
    name: "safe-defaults",
    type: "linear",
    description: "Read issues/projects/docs; creating or editing needs approval; deletes denied.",
    riskTier: "medium",
    baseUrl: "https://mcp.linear.app/sse",
    grant: {
      allow: [
        "session:*",
        "tools:list",
        "issue:read",
        "comment:read",
        "project:read",
        "doc:read",
        "milestone:read",
        "directory:read",
      ],
      require_approval: ["issue:write", "comment:write", "project:write"],
      deny: ["comment:delete", "attachment:delete", "status:delete"],
    },
  },
  {
    name: "safe-defaults",
    type: "slack",
    description: "Read channels & history; posting or reacting needs approval; uploads denied.",
    riskTier: "medium",
    baseUrl: "https://your-slack-mcp-server/sse",
    grant: {
      allow: ["session:*", "tools:list", "channel:read", "message:read", "directory:read"],
      require_approval: ["message:send", "reaction:add"],
      deny: ["file:upload"],
    },
  },
  {
    name: "read-only",
    type: "mcp",
    description: "Generic MCP: handshake + read-only tool calls (call:list_*, call:get_*).",
    riskTier: "low",
    baseUrl: "https://your-mcp-server/sse",
    grant: {
      allow: [
        "session:*",
        "tools:list",
        "resources:*",
        "prompts:*",
        "notify:*",
        "call:list_*",
        "call:get_*",
        "call:search_*",
      ],
    },
  },
];

export const templateRegistry = {
  list(filterType?: UpstreamType): readonly PolicyTemplate[] {
    return filterType ? TEMPLATES.filter((t) => t.type === filterType) : TEMPLATES;
  },
  get(type: UpstreamType, name: string): PolicyTemplate | undefined {
    return TEMPLATES.find((t) => t.type === type && t.name === name);
  },
};
