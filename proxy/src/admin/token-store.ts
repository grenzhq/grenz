/**
 * Named admin tokens for the console/admin API. Each token has a role
 * (viewer/approver/admin); the SHA-256 hash is stored, the plaintext is shown
 * once at create time and forgotten. Plain, truncatable JSON (0600) beside the
 * age identity — operational access-control state, NOT tamper-evident and NOT an
 * audit trail. A corrupt file THROWS on load so a broken store fails closed.
 */
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync } from "node:fs";
import { generateToken, hashToken } from "../util/token.ts";
import type { Role } from "./role.ts";

export class TokenStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenStoreError";
  }
}

export interface TokenRecord {
  readonly name: string;
  readonly role: Role;
  readonly tokenHash: string;
  readonly createdAt: number;
  readonly revokedAt: number | null;
  /** Federated-identity subject for a short-lived token; null for hand-minted tokens. */
  readonly subject: string | null;
  /** Absolute expiry (ms epoch) for a short-lived token; null = no expiry. */
  readonly expiresAt: number | null;
}

interface StoredShape {
  version: number;
  tokens: TokenRecord[];
}

export class TokenStore {
  private readonly path: string;
  private records: TokenRecord[];

  constructor(path: string) {
    this.path = path;
    this.records = TokenStore.load(path);
  }

  private static load(path: string): TokenRecord[] {
    if (!existsSync(path)) return [];
    let parsed: StoredShape;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8")) as StoredShape;
    } catch (err) {
      throw new TokenStoreError(
        `corrupt admin-tokens file at ${path}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!parsed || !Array.isArray(parsed.tokens)) {
      throw new TokenStoreError(`malformed admin-tokens file at ${path}`);
    }
    // Backfill legacy rows that predate the subject/expiresAt fields so older
    // files still load; present values win.
    return parsed.tokens.map((t) => ({ ...t, subject: t.subject ?? null, expiresAt: t.expiresAt ?? null }));
  }

  /** Mint a named token. Async — the secret is hashed. Rejects a duplicate LIVE
   *  name (a revoked name may be reused). */
  async create(name: string, role: Role, now: number): Promise<{ token: string; record: TokenRecord }> {
    if (this.records.some((r) => r.name === name && r.revokedAt === null)) {
      throw new TokenStoreError(`a live admin token named "${name}" already exists`);
    }
    const token = generateToken("grenz-adm");
    const record: TokenRecord = {
      name,
      role,
      tokenHash: await hashToken(token),
      createdAt: now,
      revokedAt: null,
      subject: null,
      expiresAt: null,
    };
    this.records.push(record);
    this.persist();
    return { token, record };
  }

  /** Resolve a token HASH to a live identity, or null if unknown/revoked/expired. */
  resolve(tokenHash: string, now: number): { name: string; role: Role; subject: string | null } | null {
    const rec = this.records.find(
      (r) => r.tokenHash === tokenHash && r.revokedAt === null && (r.expiresAt === null || r.expiresAt > now),
    );
    return rec ? { name: rec.name, role: rec.role, subject: rec.subject } : null;
  }

  /** All records (incl. revoked), newest first. Callers must not print the hash. */
  list(): readonly TokenRecord[] {
    return [...this.records].sort((a, b) => b.createdAt - a.createdAt);
  }

  /** Revoke the live token with this name. True if one was revoked. */
  revoke(name: string, now: number): boolean {
    const rec = this.records.find((r) => r.name === name && r.revokedAt === null);
    if (!rec) return false;
    const idx = this.records.indexOf(rec);
    this.records[idx] = { ...rec, revokedAt: now };
    this.persist();
    return true;
  }

  private persist(): void {
    const shape: StoredShape = { version: 1, tokens: this.records };
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(shape, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
    try {
      chmodSync(this.path, 0o600);
    } catch {
      /* best-effort perms */
    }
  }
}
