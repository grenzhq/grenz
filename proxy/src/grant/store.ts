/**
 * Grant store — just-in-time temporary widening of an agent's OWN token.
 *
 * Distinct from delegation: a delegation mints a NEW attenuated sub-token for
 * a spawned child, and can only narrow the parent's scope. A temporary grant
 * widens the SAME agent's existing GRENZ_TOKEN for a bounded TTL — no new
 * token is minted, so there is nothing secret to generate, hash, or hide here.
 *
 * Like the delegation and revocation stores, this is plain, truncatable JSON —
 * operational state, not tamper-evident. A corrupt file THROWS on load so the
 * proxy refuses to serve with an unknown grant set (fail closed).
 *
 * Early cutoff reuses the EXISTING kill-switch rather than a new mechanism:
 * `grenz revoke <grant-id>` against the RevocationStore, exactly like a
 * delegation is cut short by revoking its id.
 */
import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { shortId } from "../util/id.ts";

export const MAX_TTL_SECONDS = 3600; // a grant never outlives the hour
export const DEFAULT_TTL_SECONDS = 900; // 15 minutes
const MAX_REASON = 200;
const MAX_ACTIONS = 100;
/** Bounds memory/disk so a compromised admin token can't spawn grants unboundedly. */
export const MAX_ACTIVE = 1000;

export interface TemporaryGrant {
  readonly id: string;
  readonly agentId: string;
  readonly actions: readonly string[];
  readonly reason: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export class GrantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GrantError";
  }
}

interface StoredShape {
  version: number;
  grants: Record<string, Omit<TemporaryGrant, "id">>;
}

export interface MintInput {
  readonly agentId: string;
  readonly actions: readonly string[];
  readonly ttlMs: number;
  readonly reason: string;
  readonly now: number;
}

export class GrantStore {
  private readonly path: string;
  private byId: Map<string, TemporaryGrant>;

  constructor(path: string) {
    this.path = path;
    this.byId = GrantStore.load(path);
  }

  /** Mint a temporary grant. Synchronous — no credential material to hash. */
  mint(input: MintInput): TemporaryGrant {
    const grant: TemporaryGrant = {
      id: shortId("grant"),
      agentId: input.agentId,
      actions: [...input.actions].slice(0, MAX_ACTIONS),
      reason: input.reason.slice(0, MAX_REASON),
      createdAt: input.now,
      expiresAt: input.now + input.ttlMs,
    };
    this.byId.set(grant.id, grant);
    this.persist();
    return grant;
  }

  /** True when the live-grant count is at the cap (mint should refuse). */
  atCapacity(now: number): boolean {
    return this.list(now).length >= MAX_ACTIVE;
  }

  get(id: string): TemporaryGrant | undefined {
    return this.byId.get(id);
  }

  /** Active (non-expired) grants, newest first. */
  list(now: number): TemporaryGrant[] {
    return [...this.byId.values()]
      .filter((g) => g.expiresAt > now)
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  /** Drop expired records and rewrite the file. Returns how many were purged. */
  purgeExpired(now: number): number {
    let purged = 0;
    for (const [id, g] of this.byId) {
      if (g.expiresAt <= now) {
        this.byId.delete(id);
        purged++;
      }
    }
    if (purged > 0) this.persist();
    return purged;
  }

  private persist(): void {
    const shape: StoredShape = { version: 1, grants: {} };
    for (const g of this.byId.values()) {
      shape.grants[g.id] = {
        agentId: g.agentId,
        actions: g.actions,
        reason: g.reason,
        createdAt: g.createdAt,
        expiresAt: g.expiresAt,
      };
    }
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(shape, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  private static load(path: string): Map<string, TemporaryGrant> {
    if (!existsSync(path)) return new Map();
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new GrantError(`grants file is not valid JSON: ${path}`);
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new GrantError(`grants file is malformed: ${path}`);
    }
    const grantsObj = (parsed as Record<string, unknown>).grants;
    if (typeof grantsObj !== "object" || grantsObj === null) {
      throw new GrantError(`grants file is malformed: ${path}`);
    }
    const map = new Map<string, TemporaryGrant>();
    for (const [id, raw] of Object.entries(grantsObj as Record<string, unknown>)) {
      if (typeof raw !== "object" || raw === null) continue;
      const r = raw as Record<string, unknown>;
      if (typeof r.agentId !== "string") continue;
      const actions = Array.isArray(r.actions)
        ? r.actions.filter((a): a is string => typeof a === "string")
        : [];
      map.set(id, {
        id,
        agentId: r.agentId,
        actions,
        reason: typeof r.reason === "string" ? r.reason : "",
        createdAt: typeof r.createdAt === "number" ? r.createdAt : 0,
        expiresAt: typeof r.expiresAt === "number" ? r.expiresAt : 0,
      });
    }
    return map;
  }
}
