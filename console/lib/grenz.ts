/**
 * Server-side access to the Grenz proxy's loopback admin API.
 *
 * The admin token stays on the server (never sent to the browser). It is read
 * from `GRENZ_ADMIN_TOKEN`, or from `admin.token` inside the Grenz home
 * (`GRENZ_HOME`, defaulting to `../.grenz` relative to this app). The proxy
 * URL comes from `GRENZ_PROXY_URL` (default `http://127.0.0.1:8787`).
 */
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

export interface GrenzAccess {
  readonly proxyUrl: string;
  readonly token: string;
}

export function grenzAccess(): GrenzAccess {
  const proxyUrl = process.env.GRENZ_PROXY_URL ?? "http://127.0.0.1:8787";
  let token = process.env.GRENZ_ADMIN_TOKEN;
  if (!token) {
    const home = process.env.GRENZ_HOME ?? resolve(process.cwd(), "..", ".grenz");
    token = readFileSync(join(home, "admin.token"), "utf8").trim();
  }
  return { proxyUrl, token };
}

/** Forward a request to the proxy admin API, injecting the admin token.
 *
 * A timeout is essential: if something other than a live Grenz proxy is holding
 * the port (a wedged process, a stale Docker port-forward with no container
 * behind it), the socket accepts the connection but never answers. Without a
 * deadline the fetch — and the console page waiting on it — hangs forever and
 * renders a blank screen. The timeout turns that into a clean "not responding"
 * error the UI already knows how to show. */
const PROXY_TIMEOUT_MS = 4000;

export async function proxyFetch(path: string, init?: RequestInit): Promise<Response> {
  const { proxyUrl, token } = grenzAccess();
  return fetch(`${proxyUrl}${path}`, {
    ...init,
    headers: { ...(init?.headers ?? {}), "x-grenz-admin": token },
    cache: "no-store",
    signal: AbortSignal.timeout(PROXY_TIMEOUT_MS),
  });
}

const JSON_HEADERS = { "content-type": "application/json" } as const;

/**
 * Forward to the proxy and re-emit its JSON to the browser. A failure to reach
 * the proxy (or read the admin token) surfaces as a structured 502 the UI can
 * render, rather than crashing the route.
 */
export async function forwardJson(path: string, init?: RequestInit): Promise<Response> {
  try {
    const res = await proxyFetch(path, init);
    return new Response(await res.text(), { status: res.status, headers: JSON_HEADERS });
  } catch (err) {
    // A timeout means something is holding the port but not answering as a Grenz
    // proxy (a wedged process or a stale Docker forward); a connection error
    // means nothing is there at all. The two call for different fixes, so say
    // which one it is rather than a single vague "unreachable".
    const timedOut = err instanceof DOMException && err.name === "TimeoutError";
    return new Response(
      JSON.stringify(
        timedOut
          ? { error: "proxy_timeout", hint: "something is on the proxy port but not answering as Grenz — a stale Docker container or another process may be holding it" }
          : { error: "proxy_unreachable", hint: "is `grenz run` running?" },
      ),
      { status: timedOut ? 504 : 502, headers: JSON_HEADERS },
    );
  }
}
