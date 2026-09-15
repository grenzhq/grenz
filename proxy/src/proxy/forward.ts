/**
 * Forward an allowed request to the upstream, injecting the real credential.
 *
 * This is the ONLY place a real credential touches a request, and it only ever
 * flows OUTWARD (proxy -> upstream). The agent's GRENZ_TOKEN is stripped before
 * forwarding, and the credential is never copied onto the response returned to
 * the agent. Violating either of those is a critical bug (invariants 1 & 2).
 */
import type { RealUpstreamConfig } from "../config/schema.ts";
import { capResponseBody } from "../response/cap.ts";
import type { ResolvedResponseLimit } from "../response/limit.ts";

/** Hop-by-hop and identity headers we must not copy through in either direction. */
const STRIP_REQUEST_HEADERS = new Set([
  "host",
  "authorization",
  "x-grenz-token",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
]);

const STRIP_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-encoding", // fetch already decoded the body
  "content-length",
  // An upstream session cookie minted for the injected credential is a
  // credential-equivalent; do not hand it back to the agent to reuse directly.
  "set-cookie",
]);

export interface ForwardParams {
  readonly upstream: RealUpstreamConfig;
  readonly credential: string;
  readonly method: string;
  /** The already-origin-validated outbound URL (see proxy/egress.ts). */
  readonly url: string;
  readonly requestHeaders: Headers;
  readonly body: Uint8Array | null;
  /** Optional response-size cap resolved from policy for this request. */
  readonly responseLimit?: ResolvedResponseLimit;
}

export type ForwardResult =
  | { readonly outcome: "ok" | "truncated"; readonly response: Response; readonly status: number }
  | { readonly outcome: "too_large"; readonly status: number };

export async function forward(params: ForwardParams): Promise<ForwardResult> {
  const { upstream, credential } = params;

  const headers = new Headers();
  for (const [key, value] of params.requestHeaders) {
    if (!STRIP_REQUEST_HEADERS.has(key.toLowerCase())) headers.set(key, value);
  }

  // Inject the real credential. This is the credential's only appearance.
  const scheme = upstream.inject.scheme;
  const injected = scheme.length > 0 ? `${scheme} ${credential}` : credential;
  headers.set(upstream.inject.header, injected);

  // GitHub rejects requests without a User-Agent.
  if (upstream.type === "github" && !headers.has("user-agent")) {
    headers.set("user-agent", "grenz-proxy");
  }

  const url = params.url;
  const hasBody = params.body !== null && params.body.byteLength > 0;

  const upstreamResponse = await fetch(url, {
    method: params.method,
    headers,
    body: hasBody ? params.body : undefined,
    redirect: "manual",
  });

  // Rebuild a clean response for the agent. The credential we injected lives
  // only on the outbound request above and is never on this object. The body is
  // streamed straight through (so MCP SSE streams and large payloads are not
  // buffered); `fetch` has already decoded any content-encoding, so we strip
  // that header (and content-length) to avoid a double-decode by the client.
  const responseHeaders = new Headers();
  for (const [key, value] of upstreamResponse.headers) {
    if (!STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) responseHeaders.set(key, value);
  }
  responseHeaders.set("x-grenz-decision", "allow");

  const limit = params.responseLimit;
  if (limit) {
    // content-length is the RAW upstream header (already stripped from
    // responseHeaders above, so a capped body never advertises the original
    // length). A malformed value is treated as unknown (no fail-fast deny).
    const clRaw = upstreamResponse.headers.get("content-length");
    const declared = clRaw !== null && /^\d+$/.test(clRaw) ? Number(clRaw) : null;

    // Declared oversize under `deny` → refuse before any body reaches the agent.
    if (limit.onExceed === "deny" && declared !== null && declared > limit.maxBytes) {
      void upstreamResponse.body?.cancel().catch(() => {}); // let the socket close
      return { outcome: "too_large", status: upstreamResponse.status };
    }

    // A cap is in effect. The counting passthrough cuts the stream at the cap;
    // content-length is stripped, so the client reads to stream-close.
    responseHeaders.set("x-grenz-response-limit", String(limit.maxBytes));
    const knownExceeds = declared !== null && declared > limit.maxBytes;
    if (knownExceeds) responseHeaders.set("x-grenz-truncated", "true");
    const { stream } = capResponseBody(
      upstreamResponse.body as ReadableStream<Uint8Array> | null,
      limit.maxBytes,
    );
    const response = new Response(stream, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
    return { outcome: knownExceeds ? "truncated" : "ok", response, status: upstreamResponse.status };
  }

  const response = new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
  return { outcome: "ok", response, status: upstreamResponse.status };
}
