import { forwardJson } from "@/lib/grenz";

export const dynamic = "force-dynamic";

const JSON_HEADERS = { "content-type": "application/json" } as const;

export async function POST(
  _req: Request,
  ctx: { params: Promise<{ id: string; action: string }> },
): Promise<Response> {
  const { id, action } = await ctx.params;
  if (action !== "approve" && action !== "deny") {
    return new Response(JSON.stringify({ error: "bad_action" }), { status: 400, headers: JSON_HEADERS });
  }
  return forwardJson(`/console/approvals/${encodeURIComponent(id)}/${action}`, { method: "POST" });
}
