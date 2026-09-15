import { forwardJson } from "@/lib/grenz";

export const dynamic = "force-dynamic";

const JSON_HEADERS = { "content-type": "application/json" } as const;

const MAX_REASON = 200;

/** Revoke an agent (kill-switch). Reason travels in the body; the proxy reads
 *  it from the query string, so we URL-encode it there. Admin-gated upstream. */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await ctx.params;
  const body = (await req.json().catch(() => ({}))) as { reason?: unknown };
  const reason =
    typeof body.reason === "string" && body.reason.trim() ? body.reason.trim().slice(0, MAX_REASON) : "manual";
  return forwardJson(
    `/console/revocations/${encodeURIComponent(id)}?reason=${encodeURIComponent(reason)}`,
    { method: "POST" },
  );
}

/** Restore (lift a local revocation). Admin-gated upstream. */
export async function DELETE(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await ctx.params;
  if (!id) {
    return new Response(JSON.stringify({ error: "bad_id" }), { status: 400, headers: JSON_HEADERS });
  }
  return forwardJson(`/console/revocations/${encodeURIComponent(id)}`, { method: "DELETE" });
}
