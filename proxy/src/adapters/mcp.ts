/**
 * MCP (Model Context Protocol) adapters for Streamable HTTP transport.
 *
 * Client → server messages are JSON-RPC 2.0 over HTTP POST. Each message maps to
 * a normalized action:
 *   tools/call    name=X   -> `call:X`  (or a semantic action, see below)
 *   tools/list             -> `tools:list`
 *   resources/read         -> `resources:read`
 *   prompts/get            -> `prompts:get`
 *   initialize | ping      -> `session:initialize` | `session:ping`
 *   notifications/*        -> `notify:<rest>`
 *   <other>/<sub>          -> `<other>:<sub>`
 * GET (open the server→client SSE stream) -> `session:stream`;
 * DELETE (end session) -> `session:end`. Batches map one action per message.
 *
 * The GENERIC adapter maps a tool call to `call:<toolName>`. Server-specific
 * adapters (Linear, Slack) pass a `mapTool` that normalizes known tool names
 * into a canonical taxonomy (e.g. `create_issue` -> `issue:create`), falling
 * back to `call:<toolName>` for anything unknown — so a policy still fails
 * closed on tools it has not explicitly allowed.
 */
import type { AdapterOutcome, AdapterRequest, UpstreamAdapter } from "./types.ts";

/** Maps an MCP tool name to a canonical action, or null to use `call:<name>`. */
export type McpToolMapper = (toolName: string) => string | null;

/**
 * Transport actions that ANY MCP session produces, independent of the server's
 * tool set: the handshake, the server→client stream, teardown, and tool
 * discovery. Server-specific adapters (Linear, Slack) are built on this
 * transport and emit them too, so a policy has to allow them for an agent to
 * connect at all — which is why they belong in those adapters' vocabularies.
 */
export const MCP_TRANSPORT_ACTIONS: readonly string[] = [
  "session:initialize",
  "session:ping",
  "session:stream",
  "session:end",
  "tools:list",
];

interface JsonRpcMessage {
  method?: unknown;
  params?: unknown;
}

function toolName(msg: JsonRpcMessage): string | null {
  const params = msg.params;
  const name =
    params && typeof params === "object" && "name" in params
      ? (params as { name?: unknown }).name
      : undefined;
  return typeof name === "string" && name.length > 0 ? name : null;
}

function actionForMessage(msg: JsonRpcMessage, mapTool?: McpToolMapper): string | { error: string } {
  const method = msg.method;
  if (typeof method !== "string" || method.length === 0) {
    return { error: "JSON-RPC message missing string `method`" };
  }

  if (method === "tools/call") {
    const name = toolName(msg);
    if (name === null) return { error: "tools/call missing string `params.name`" };
    const mapped = mapTool ? mapTool(name) : null;
    return mapped ?? `call:${name}`;
  }

  if (method === "initialize") return "session:initialize";
  if (method === "ping") return "session:ping";
  if (method.startsWith("notifications/")) return `notify:${method.slice("notifications/".length)}`;

  const slash = method.indexOf("/");
  if (slash > 0) return `${method.slice(0, slash)}:${method.slice(slash + 1)}`;
  return method;
}

function labelForMessage(msg: JsonRpcMessage): string {
  const method = typeof msg.method === "string" ? msg.method : "?";
  if (method === "tools/call") {
    const name = toolName(msg);
    if (name) return `tools/call ${name}`;
  }
  return method;
}

/** How many batch members the display label names before eliding the rest. */
const BATCH_LABEL_MEMBERS = 3;

/**
 * The DISPLAY label for a multi-message batch: `batch(N): a, b, +M more`.
 *
 * A bare `batch(N)` tells a human approving the request nothing about what they
 * are approving, so the label names the first few members. Bounded on purpose —
 * this string reaches log lines and approval prompts. It is never a matching
 * input; every gate uses the per-message `targets`.
 */
function batchLabel(labels: readonly string[]): string {
  const head = labels.slice(0, BATCH_LABEL_MEMBERS).join(", ");
  const rest = labels.length - BATCH_LABEL_MEMBERS;
  return `batch(${labels.length}): ${head}${rest > 0 ? `, +${rest} more` : ""}`;
}

/** Build an MCP adapter of the given `type`, optionally with a semantic tool map. */
export function createMcpAdapter(type: string, mapTool?: McpToolMapper): UpstreamAdapter {
  return {
    type,
    map(req: AdapterRequest): AdapterOutcome {
      if (req.method === "GET") {
        return { actions: ["session:stream"], targets: ["GET stream"], target: "GET stream", label: "GET" };
      }
      if (req.method === "DELETE") {
        return { actions: ["session:end"], targets: ["DELETE session"], target: "DELETE session", label: "DELETE" };
      }
      if (req.method !== "POST") {
        return { unsupported: `unsupported MCP method: ${req.method}` };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder().decode(req.body));
      } catch {
        return { unsupported: "invalid JSON-RPC body" };
      }

      const messages = Array.isArray(parsed) ? parsed : [parsed];
      if (messages.length === 0) return { unsupported: "empty JSON-RPC batch" };

      const actions: string[] = [];
      const labels: string[] = [];
      for (const raw of messages) {
        if (raw === null || typeof raw !== "object") {
          return { unsupported: "JSON-RPC message is not an object" };
        }
        const result = actionForMessage(raw as JsonRpcMessage, mapTool);
        if (typeof result !== "string") return { unsupported: result.error };
        actions.push(result);
        labels.push(labelForMessage(raw as JsonRpcMessage));
      }

      // `labels` is the per-message target, one per action — that is what every
      // scoped gate matches on. `target` is only the display label: collapsing a
      // batch to `batch(N)` for MATCHING would let a batched message slip past a
      // target-scoped deny/tripwire/cap, since no real glob matches that literal.
      const target = messages.length === 1 ? labels[0]! : batchLabel(labels);
      const label = messages.length === 1 ? "POST" : "POST batch";
      return { actions, targets: labels, target, label };
    },
  };
}

/** The generic MCP adapter: matches on the server's real tool names. */
export const mcpAdapter: UpstreamAdapter = createMcpAdapter("mcp");
