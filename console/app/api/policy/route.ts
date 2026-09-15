import { forwardJson } from "@/lib/grenz";

export const dynamic = "force-dynamic";

export function GET(): Promise<Response> {
  return forwardJson("/console/policy");
}

export async function POST(request: Request): Promise<Response> {
  const body = await request.text();
  return forwardJson("/console/policy", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}
