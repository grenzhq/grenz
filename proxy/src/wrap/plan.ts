/**
 * `grenz wrap` — pure classification core (no I/O, no secrets in output).
 *
 * Reads an MCP client config and decides, per server, whether it can be pulled
 * behind Grenz. Secret VALUES are read only to classify them (literal vs a
 * `${ref}` vs a url-embedded credential); they are NEVER stored in the plan or
 * reproduced anywhere — the advisor emits a `grenz vault set` line the user runs
 * against their own file, so the secret never passes through Grenz's output.
 *
 * Grenz is an HTTP reverse proxy (`/u/<upstream>`), so only remote servers
 * (http/streamable-http/sse/ws) are wrappable; a stdio server is a local
 * subprocess Grenz cannot front. A server is wrapped whole or skipped whole with
 * a reason — never half-transformed.
 */

/** Raised for a malformed config. Its message NEVER contains config source or a
 *  secret — a JSON error snippet can sit one character from a token. */
export class WrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrapError";
  }
}

export interface ListenAddr {
  readonly host: string;
  readonly port: number;
}

export interface McpConfig {
  /** The parsed document (unknown fields preserved for a future rewrite). */
  readonly doc: Record<string, unknown>;
  readonly servers: Record<string, Record<string, unknown>>;
}

export type ServerPlan =
  | {
      readonly name: string;
      readonly action: "wrap";
      readonly url: string;
      /** Original-case header name carrying the literal credential. */
      readonly header: string;
      /** `Bearer` (etc.) when the value is `<scheme> <secret>`, else "". */
      readonly scheme: string;
      /** Vault key the advisor tells the user to store the secret under. */
      readonly vaultKey: string;
      /** Grenz upstream name. */
      readonly upstream: string;
    }
  | { readonly name: string; readonly action: "skip"; readonly reason: string };

export interface WrapPlan {
  readonly servers: ServerPlan[];
}

/** Header names (case-insensitive) that carry credentials worth moving. */
const CREDENTIAL_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "x-api-token",
  "x-auth-token",
  "x-access-token",
  "x-goog-api-key",
]);

/** Query-param names that, when present with a value, mean the url carries a
 *  credential we must not copy into grenz.yaml or print. */
const CREDENTIAL_QUERY_PARAMS = new Set(["token", "key", "apikey", "api_key", "access_token", "secret", "auth"]);

const REMOTE_TYPES = new Set(["http", "streamable-http", "sse", "ws"]);

export function parseMcpConfig(text: string): McpConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Deliberately generic: a JSON error message/snippet can echo a nearby token.
    throw new WrapError("config is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new WrapError("config is not a JSON object");
  }
  const doc = parsed as Record<string, unknown>;
  const rawServers = doc.mcpServers;
  const servers: Record<string, Record<string, unknown>> = {};
  if (rawServers !== undefined && rawServers !== null) {
    if (typeof rawServers !== "object" || Array.isArray(rawServers)) {
      throw new WrapError("mcpServers is not an object");
    }
    for (const [name, entry] of Object.entries(rawServers as Record<string, unknown>)) {
      if (typeof entry === "object" && entry !== null && !Array.isArray(entry)) {
        servers[name] = entry as Record<string, unknown>;
      }
    }
  }
  return { doc, servers };
}

/** A header value is a reference (already externalized), not a literal secret,
 *  if it contains `${` anywhere — covers `${T}`, `${T:-d}`, `Bearer ${T}`. */
function isReference(value: string): boolean {
  return value.includes("${");
}

/** Split `Bearer <secret>` → {scheme:"Bearer"}; a bare token → {scheme:""}. */
function scheme(value: string): string {
  const m = /^(\S+)\s+\S/.exec(value.trim());
  return m ? m[1]! : "";
}

function slug(header: string): string {
  return header.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function isStdio(entry: Record<string, unknown>): boolean {
  if (entry.type === "stdio") return true;
  // No declared type but a command and no url → a local subprocess.
  return entry.type === undefined && typeof entry.command === "string" && entry.url === undefined;
}

/** null = fine; a string = the skip reason because the url itself carries a secret. */
function urlCredentialReason(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null; // not our job to validate the url shape here
  }
  if (u.username !== "" || u.password !== "") return "url embeds a credential (userinfo) — not wrappable in v1";
  for (const [k, v] of u.searchParams) {
    if (v !== "" && CREDENTIAL_QUERY_PARAMS.has(k.toLowerCase())) {
      return "url embeds a credential (query param) — not wrappable in v1";
    }
  }
  return null;
}

function isAlreadyWrapped(url: string, listen: ListenAddr): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  const loopback = new Set(["127.0.0.1", "localhost", "[::1]", "::1", listen.host]);
  return loopback.has(u.hostname) && u.pathname.startsWith("/u/");
}

function classify(name: string, entry: Record<string, unknown>, listen: ListenAddr): ServerPlan {
  if (isStdio(entry)) {
    return { name, action: "skip", reason: "stdio server — Grenz fronts a network endpoint, not a local subprocess" };
  }
  const type = entry.type;
  const url = typeof entry.url === "string" ? entry.url : undefined;
  const isRemote = (typeof type === "string" && REMOTE_TYPES.has(type)) || url !== undefined;
  if (!isRemote) {
    return { name, action: "skip", reason: "not a remote server — nothing to front" };
  }
  if (url === undefined) {
    return { name, action: "skip", reason: "remote server without a url" };
  }
  if (isAlreadyWrapped(url, listen)) {
    return { name, action: "skip", reason: "already wrapped (url points at the Grenz listener)" };
  }
  const urlReason = urlCredentialReason(url);
  if (urlReason !== null) {
    return { name, action: "skip", reason: urlReason };
  }

  const headers = entry.headers;
  const literalCreds: Array<{ header: string; value: string }> = [];
  let sawReference = false;
  if (typeof headers === "object" && headers !== null && !Array.isArray(headers)) {
    for (const [hname, hval] of Object.entries(headers as Record<string, unknown>)) {
      if (typeof hval !== "string") continue;
      if (!CREDENTIAL_HEADERS.has(hname.toLowerCase())) continue;
      if (isReference(hval)) {
        sawReference = true;
      } else {
        literalCreds.push({ header: hname, value: hval });
      }
    }
  }

  if (literalCreds.length === 0) {
    if (sawReference) {
      return { name, action: "skip", reason: "credential already externalized (a ${VAR} reference)" };
    }
    return { name, action: "skip", reason: "no credential header to move" };
  }
  if (literalCreds.length > 1) {
    return { name, action: "skip", reason: "multiple credential headers — not representable as one upstream in v1" };
  }
  const cred = literalCreds[0]!;
  return {
    name,
    action: "wrap",
    url,
    header: cred.header,
    scheme: scheme(cred.value),
    vaultKey: `${slug(name)}__${slug(cred.header)}`,
    upstream: slug(name),
  };
}

export function planWrap(config: McpConfig, listen: ListenAddr): WrapPlan {
  const servers = Object.entries(config.servers).map(([name, entry]) => classify(name, entry, listen));
  return { servers };
}
