/**
 * Action vocabularies: the full set of canonical actions each adapter TYPE
 * can produce, when known. Used by the blast-radius analyzer to expand a
 * glob grant (`repo:*`) into concrete actions instead of just echoing the
 * pattern back. A `null` vocabulary means the type accepts arbitrary tool
 * names (the generic `mcp` adapter) and cannot be enumerated statically.
 */
import { GITHUB_ACTIONS } from "./github.ts";
import { LINEAR_ACTION_LIST } from "./linear.ts";
import { SLACK_ACTION_LIST } from "./slack.ts";
import { MCP_TRANSPORT_ACTIONS } from "./mcp.ts";

// Linear and Slack are semantic layers over the MCP transport, so a real
// session emits the transport actions as well as the mapped ones. Leaving them
// out made `grenz policy lint` report `session:*` and `tools:list` as dead
// patterns — advising an operator to delete the rules the handshake requires.
// GitHub is REST and has no transport actions of this kind.
const VOCABULARIES: ReadonlyMap<string, readonly string[]> = new Map([
  ["github", GITHUB_ACTIONS],
  ["linear", [...LINEAR_ACTION_LIST, ...MCP_TRANSPORT_ACTIONS]],
  ["slack", [...SLACK_ACTION_LIST, ...MCP_TRANSPORT_ACTIONS]],
]);

export function actionVocabulary(type: string): readonly string[] | null {
  return VOCABULARIES.get(type) ?? null;
}
