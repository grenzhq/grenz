import { forwardJson } from "@/lib/grenz";

export const dynamic = "force-dynamic";

const JSON_HEADERS = { "content-type": "application/json" } as const;

const MAX_REASON = 200;

export function GET(): Promise<Response> {
  return forwardJson("/console/grants");
}

/** Mint a temporary grant — widen an agent's own token for a TTL. The proxy
 *  reads its inputs from the query string (and applies every guard: admin-only,
 *  capacity, unknown-agent, empty-actions, TTL clamp), so we translate the JSON
 *  body into that query. Admin-gated upstream. */
export async function POST(req: Request): Promise<Response> {
  const body = (await req.json().catch(() => ({}))) as {
    agent?: unknown;
    actions?: unknown;
    ttl?: unknown;
    reason?: unknown;
  };
  const agent = typeof body.agent === "string" ? body.agent.trim() : "";
  const actions = typeof body.actions === "string" ? body.actions.trim() : "";
  if (!agent || !actions) {
    return new Response(JSON.stringify({ error: "missing_agent_or_actions" }), {
      status: 400,
      headers: JSON_HEADERS,
    });
  }
  const qs = new URLSearchParams({ agent, actions });
  if (typeof body.ttl === "number" && Number.isFinite(body.ttl)) qs.set("ttl", String(Math.floor(body.ttl)));
  if (typeof body.reason === "string" && body.reason.trim()) {
    qs.set("reason", body.reason.trim().slice(0, MAX_REASON));
  }
  return forwardJson(`/console/grants?${qs.toString()}`, { method: "POST" });
}
