import { forwardJson } from "@/lib/grenz";

export const dynamic = "force-dynamic";

const JSON_HEADERS = { "content-type": "application/json" } as const;

/** Mint a new agent identity. The proxy validates the id, mints the token,
 *  persists it to grenz.yaml, and registers it live — returning the raw
 *  GRENZ_TOKEN exactly once. Admin-gated upstream (x-grenz-admin). We never
 *  store or log the token here; we pass the proxy's response straight through. */
export async function POST(req: Request): Promise<Response> {
  const body = (await req.json().catch(() => ({}))) as { id?: unknown };
  const id = typeof body.id === "string" ? body.id.trim() : "";
  if (!id) {
    return new Response(JSON.stringify({ error: "missing_id" }), { status: 400, headers: JSON_HEADERS });
  }
  return forwardJson("/console/agents", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ id }),
  });
}
