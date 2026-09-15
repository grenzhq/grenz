/**
 * Break-glass windows — a loud, time-boxed, admin-pulled scope under which an
 * otherwise-DENIED action becomes approvable (see the dispatch gate). Plain,
 * truncatable JSON (0600), throw-on-corrupt fail-closed load — operational
 * emergency-access state, exactly as truncatable as GrantStore. NOT an audit
 * trail and NEVER immutable/append-only.
 */
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync } from "node:fs";
import { shortId } from "../util/id.ts";

export class BreakGlassError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BreakGlassError";
  }
}

export const DEFAULT_TTL_SECONDS = 900;
export const MAX_TTL_SECONDS = 3600;
const MAX_ACTIVE = 50;
const MAX_ACTIONS = 50;
const MAX_REASON = 200;

export interface BreakGlassRecord {
  readonly id: string;
  readonly agentId: string;
  readonly actions: readonly string[];
  readonly quorum: number;
  readonly reason: string;
  readonly pulledBy: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

interface StoredShape {
  version: number;
  windows: BreakGlassRecord[];
}

export interface PullInput {
  readonly agentId: string;
  readonly actions: readonly string[];
  readonly quorum: number;
  readonly reason: string;
  readonly pulledBy: string;
  readonly ttlMs: number;
  readonly now: number;
}

export class BreakGlassStore {
  private readonly path: string;
  private readonly maxActive: number;
  private windows: BreakGlassRecord[];

  constructor(path: string, maxActive: number = MAX_ACTIVE) {
    this.path = path;
    this.maxActive = maxActive;
    this.windows = BreakGlassStore.load(path);
  }

  private static load(path: string): BreakGlassRecord[] {
    if (!existsSync(path)) return [];
    let parsed: StoredShape;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8")) as StoredShape;
    } catch (err) {
      throw new BreakGlassError(
        `corrupt break-glass file at ${path}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!parsed || !Array.isArray(parsed.windows)) {
      throw new BreakGlassError(`malformed break-glass file at ${path}`);
    }
    return parsed.windows;
  }

  pull(input: PullInput): BreakGlassRecord {
    const rec: BreakGlassRecord = {
      id: shortId("bg"),
      agentId: input.agentId,
      actions: [...input.actions].slice(0, MAX_ACTIONS),
      quorum: Math.max(1, Math.floor(input.quorum)),
      reason: input.reason.slice(0, MAX_REASON),
      pulledBy: input.pulledBy,
      createdAt: input.now,
      expiresAt: input.now + input.ttlMs,
    };
    this.windows.push(rec);
    this.persist();
    return rec;
  }

  list(now: number): BreakGlassRecord[] {
    return this.windows.filter((w) => w.expiresAt > now).sort((a, b) => b.createdAt - a.createdAt);
  }

  atCapacity(now: number): boolean {
    return this.list(now).length >= this.maxActive;
  }

  purgeExpired(now: number): number {
    const before = this.windows.length;
    this.windows = this.windows.filter((w) => w.expiresAt > now);
    const purged = before - this.windows.length;
    if (purged > 0) this.persist();
    return purged;
  }

  private persist(): void {
    const shape: StoredShape = { version: 1, windows: this.windows };
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(shape, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
    try {
      chmodSync(this.path, 0o600);
    } catch {
      /* best-effort */
    }
  }
}
