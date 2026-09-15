import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Guard the admin-backed `/api/*` routes.
 *
 * These routes forward to the proxy's admin API with the admin token injected
 * server-side, so they must not become a cross-site confused deputy. Browsers
 * attach `Sec-Fetch-Site`; a cross-site request (e.g. a malicious page the
 * operator visits POSTing to 127.0.0.1) is rejected. Same-origin requests from
 * the console page pass. Non-browser callers (no `Sec-Fetch-Site`) are allowed —
 * for those the loopback bind is the trust boundary (see console/README.md).
 *
 * Named `proxy` per Next.js 16's file convention (the old `middleware.ts` name is
 * deprecated); behavior is unchanged.
 */
export function proxy(req: NextRequest): NextResponse {
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    return NextResponse.json({ error: "cross_site_blocked" }, { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: "/api/:path*" };
