import { forwardJson } from "@/lib/grenz";

export const dynamic = "force-dynamic";

export function GET(): Promise<Response> {
  return forwardJson("/console/summary");
}
