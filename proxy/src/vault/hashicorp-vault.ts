/**
 * Read-only HashiCorp Vault (KV v2) credential backend. Fetches upstream
 * credentials INTO the proxy post-allow; they live only in process memory and
 * are injected on the outbound request. Fails closed. The error path NEVER
 * carries secret bytes — a mis-shaped response yields a fixed string, never the
 * body (which contains the secret).
 */
import { z } from "zod";
import type { CredentialStore } from "./store.ts";
import { VaultError } from "./store.ts";

const FETCH_TIMEOUT_MS = 5000;

// Minimal shapes — parsed with safeParse; the ZodError is ALWAYS discarded so a
// mis-shaped secret body can never reach an error message.
const kvDataSchema = z.object({
  data: z.object({ data: z.record(z.string(), z.unknown()).nullable() }),
});
const kvListSchema = z.object({ data: z.object({ keys: z.array(z.string()) }) });

export interface HashicorpVaultOptions {
  readonly address: string;
  readonly mount: string;
  readonly pathPrefix: string;
  readonly field: string;
  readonly token: string;
  readonly cacheTtlMs: number;
}

export class HashicorpVaultCredentialStore implements CredentialStore {
  // Short-TTL in-memory cache (process memory only, never disk). Present values
  // only — misses and errors are never cached, so a just-fixed key recovers.
  private readonly cache = new Map<string, { value: string; fetchedAt: number }>();
  // Singleflight: coalesce concurrent in-flight fetches for the same key, so an
  // agent burst is one Vault round-trip.
  private readonly inflight = new Map<string, Promise<string | undefined>>();

  constructor(private readonly opts: HashicorpVaultOptions) {}

  private origin(): string {
    return new URL(this.opts.address).origin;
  }

  private async request(path: string): Promise<Response> {
    const url = `${this.opts.address.replace(/\/$/, "")}${path}`;
    const fetchOnce = (target: string): Promise<Response> =>
      fetch(target, {
        method: "GET",
        headers: { "x-vault-token": this.opts.token },
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    let res: Response;
    try {
      res = await fetchOnce(url);
    } catch {
      // Timeout / network error — fixed string; never echo the underlying error
      // (it could carry the URL or token).
      throw new VaultError("backend_error", "credential backend unreachable");
    }
    // Follow ONE same-origin 307 (Vault leader redirect); reject cross-origin so
    // the token is never sent off-origin.
    if (res.status === 307) {
      const loc = res.headers.get("location");
      if (!loc || new URL(loc, url).origin !== this.origin()) {
        throw new VaultError("backend_error", "credential backend redirected off-origin");
      }
      try {
        res = await fetchOnce(new URL(loc, url).toString());
      } catch {
        throw new VaultError("backend_error", "credential backend unreachable");
      }
    }
    return res;
  }

  async get(key: string): Promise<string | undefined> {
    const now = Date.now();
    const cached = this.cache.get(key);
    if (cached && now - cached.fetchedAt < this.opts.cacheTtlMs) return cached.value;

    const existing = this.inflight.get(key);
    if (existing) return existing;

    const p = this.fetchValue(key)
      .then((value) => {
        if (value !== undefined) this.cache.set(key, { value, fetchedAt: Date.now() });
        return value;
      })
      .finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  private async fetchValue(key: string): Promise<string | undefined> {
    const res = await this.request(`/v1/${this.opts.mount}/data/${this.opts.pathPrefix}${key}`);
    if (res.status === 404) return undefined;
    if (res.status !== 200) {
      throw new VaultError("backend_error", `credential backend returned ${res.status}`);
    }
    const body = await res.json().catch(() => null);
    const parsed = kvDataSchema.safeParse(body);
    if (!parsed.success) {
      throw new VaultError("corrupt", "unexpected response shape from credential backend");
    }
    const data = parsed.data.data.data;
    if (data === null) return undefined; // soft-deleted version
    const value = data[this.opts.field];
    return typeof value === "string" ? value : undefined;
  }

  async keys(): Promise<string[]> {
    const res = await this.request(`/v1/${this.opts.mount}/metadata/${this.opts.pathPrefix}?list=true`);
    if (res.status === 404) return [];
    if (res.status !== 200) {
      throw new VaultError("backend_error", `credential backend returned ${res.status}`);
    }
    const body = await res.json().catch(() => null);
    const parsed = kvListSchema.safeParse(body);
    if (!parsed.success) {
      throw new VaultError("corrupt", "unexpected response shape from credential backend");
    }
    return parsed.data.data.keys;
  }
}
