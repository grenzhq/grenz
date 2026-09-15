/** Adapter registry, keyed by upstream `type`. */
import type { UpstreamAdapter } from "./types.ts";
import { githubAdapter } from "./github.ts";
import { mcpAdapter } from "./mcp.ts";
import { linearAdapter } from "./linear.ts";
import { slackAdapter } from "./slack.ts";

const ADAPTERS: ReadonlyMap<string, UpstreamAdapter> = new Map(
  [githubAdapter, mcpAdapter, linearAdapter, slackAdapter].map((a) => [a.type, a]),
);

export function adapterFor(type: string): UpstreamAdapter | undefined {
  return ADAPTERS.get(type);
}

export { githubAdapter, mcpAdapter, linearAdapter, slackAdapter };
export type { UpstreamAdapter } from "./types.ts";
