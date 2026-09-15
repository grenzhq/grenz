/**
 * Revocation store — the kill-switch.
 *
 * A revoked agent is cut off at the door: the proxy denies its every request
 * BEFORE upstream resolution, policy evaluation, or any credential fetch. This
 * is the response half of the risk signal — detect a compromised or
 * prompt-injected agent, then pull its plug without restarting the proxy.
 *
 * Backed by a plain JSON file in the Grenz home. Like the request log, this is
 * operational state, not a credential and not tamper-evident: no integrity
 * guarantees, truncatable by design. The RUNNING proxy owns one instance; the
 * `grenz` CLI's admin-API path mutates THAT instance, so a revocation takes
 * effect mid-flight. When the proxy is not running, the CLI writes the same
 * file directly and it is loaded on the next `grenz run`.
 *
 * A corrupt file THROWS on load: the proxy refuses to serve with an unknown
 * kill-list rather than silently treating everyone as un-revoked (fail closed).
 *
 * Revocation is keyed by agent id — the human-meaningful unit that `grenz
 * risk` reports and, with one token per agent today, exactly the token being
 * cut. Nothing here ever holds credential material.
 */
import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";

export interface RevocationRecord {
  readonly agentId: string;
  /** When the agent was revoked (ms epoch). */
  readonly ts: number;
  /** Free-text, log-safe note (e.g. "risk:high"). Never a credential. */
  readonly reason: string;
}

/** Raised when the revocations file exists but cannot be trusted. */
export class RevocationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RevocationError";
  }
}

interface FileShape {
  version: number;
  revoked: Record<string, { ts: number; reason: string }>;
}

const MAX_REASON = 200;

export class RevocationStore {
  private readonly path: string;
  private revoked: Map<string, RevocationRecord>;

  constructor(path: string) {
    this.path = path;
    this.revoked = RevocationStore.load(path);
  }

  /** True if this agent is currently cut off. Pure, in-memory — hot-path safe. */
  isRevoked(agentId: string): boolean {
    return this.revoked.has(agentId);
  }

  get(agentId: string): RevocationRecord | undefined {
    return this.revoked.get(agentId);
  }

  /** All active revocations, newest first. */
  list(): RevocationRecord[] {
    return [...this.revoked.values()].sort((a, b) => b.ts - a.ts);
  }

  /** Revoke an agent now. Idempotent; returns the stored record. */
  revoke(agentId: string, reason: string, now: number): RevocationRecord {
    const rec: RevocationRecord = { agentId, ts: now, reason: reason.slice(0, MAX_REASON) };
    this.revoked.set(agentId, rec);
    this.persist();
    return rec;
  }

  /** Lift a revocation. Returns true if the agent had been revoked. */
  restore(agentId: string): boolean {
    const had = this.revoked.delete(agentId);
    if (had) this.persist();
    return had;
  }

  /** Re-read the file (e.g. after an out-of-band CLI write). Throws on corrupt. */
  reload(): void {
    this.revoked = RevocationStore.load(this.path);
  }

  private persist(): void {
    const shape: FileShape = { version: 1, revoked: {} };
    for (const rec of this.revoked.values()) {
      shape.revoked[rec.agentId] = { ts: rec.ts, reason: rec.reason };
    }
    // Write-then-rename so a crash mid-write cannot leave a half-written file
    // that would fail closed and refuse to start the proxy.
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(shape, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  private static load(path: string): Map<string, RevocationRecord> {
    if (!existsSync(path)) return new Map();
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new RevocationError(`revocations file is not valid JSON: ${path}`);
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new RevocationError(`revocations file is malformed: ${path}`);
    }
    const revokedObj = (parsed as Record<string, unknown>).revoked;
    if (typeof revokedObj !== "object" || revokedObj === null) {
      throw new RevocationError(`revocations file is malformed: ${path}`);
    }
    const map = new Map<string, RevocationRecord>();
    for (const [agentId, raw] of Object.entries(revokedObj as Record<string, unknown>)) {
      if (typeof raw !== "object" || raw === null) continue;
      const rec = raw as Record<string, unknown>;
      const ts = typeof rec.ts === "number" ? rec.ts : 0;
      const reason = typeof rec.reason === "string" ? rec.reason.slice(0, MAX_REASON) : "";
      map.set(agentId, { agentId, ts, reason });
    }
    return map;
  }
}
