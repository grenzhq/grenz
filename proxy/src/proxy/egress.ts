/**
 * Egress guard — pins the credential-bearing outbound request to the upstream's
 * exact origin. Pure and synchronous.
 *
 * Builds the outbound URL exactly as forwarding always has (string
 * concatenation, so a base_url path prefix like `/api/v3` survives), then
 * requires the resolved origin (scheme + host + port) to equal base_url's
 * origin. Anything else -> { ok: false }, which the caller turns into an
 * `egress_blocked` DENY. This is the one enforced guarantee that the injected
 * credential can only ever reach the configured upstream host.
 */

export type EgressResolution =
  | { readonly ok: true; readonly url: string }
  | { readonly ok: false };

/** Build the outbound URL, mirroring the historical buildTargetUrl exactly. */
export function buildTargetUrl(baseUrl: string, path: string, query: string): string {
  const base = baseUrl.replace(/\/+$/, "");
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return query ? `${base}${suffix}?${query}` : `${base}${suffix}`;
}

export function resolveUpstreamUrl(baseUrl: string, path: string, query: string): EgressResolution {
  // The router always yields a single-slash-rooted pathname. A `//host`
  // (protocol-relative authority) or a non-rooted value is suspicious — reject
  // it rather than relying on concatenation to neutralize it.
  if (!path.startsWith("/") || path.startsWith("//")) {
    return { ok: false };
  }
  const candidate = buildTargetUrl(baseUrl, path, query);
  try {
    const base = new URL(baseUrl);
    const target = new URL(candidate);
    if (target.origin !== base.origin) return { ok: false };
    return { ok: true, url: candidate };
  } catch {
    return { ok: false };
  }
}
