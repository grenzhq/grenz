/**
 * FleetRevocationStore — the cached, verified fleet kill-set.
 *
 * Holds the accepted current-state set (Set<string>), its version, and its
 * optional signed expiry. Persisted to `fleet-revocations.json` (0600,
 * tmp+rename) so a restart DURING a plane outage keeps enforcing rather than
 * silently un-revoking the fleet — persistence is the security property here,
 * not a convenience. A corrupt file THROWS (fail-closed): refuse to serve with
 * an unknown fleet kill-list.
 *
 * The persisted `version` IS the anti-rollback floor: unlike the policy artifact
 * (which the proxy doesn't cache, so its floor lives in a separate file), the
 * set is cached, so one atomically-written file can never disagree with itself.
 *
 * `has()` is a pure in-memory Set lookup — hot-path safe. This never holds
 * credential material, and (bright line) never a reason, actor, or timestamp of
 * WHY an agent was cut off: those stay local, unsigned, and truncatable.
 */
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync } from "node:fs";

export class FleetRevocationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FleetRevocationError";
  }
}

interface FileShape {
  version: number;
  expiresAt: number | null;
  revokedAgents: string[];
}

export class FleetRevocationStore {
  private readonly path: string;
  private revoked: Set<string>;
  private ver: number;
  private expiry: number | null;

  constructor(path: string) {
    this.path = path;
    const loaded = FleetRevocationStore.load(path);
    this.revoked = loaded.set;
    this.ver = loaded.version;
    this.expiry = loaded.expiresAt;
  }

  has(agentId: string): boolean {
    return this.revoked.has(agentId);
  }

  floor(): number {
    return this.ver;
  }

  version(): number {
    return this.ver;
  }

  expiresAt(): number | null {
    return this.expiry;
  }

  count(): number {
    return this.revoked.size;
  }

  list(): string[] {
    return [...this.revoked].sort();
  }

  /**
   * Swap the whole set. Persist FIRST, then update memory: a persist failure
   * throws and leaves the last-good set enforced (fail-static in the safe
   * direction). Callers must have already verified `version >= floor()`.
   */
  replace(agents: readonly string[], version: number, expiresAt: number | null, _now: number): void {
    const next = new Set(agents);
    const shape: FileShape = { version, expiresAt, revokedAgents: [...next].sort() };
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(shape, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.path);
    try {
      chmodSync(this.path, 0o600);
    } catch {
      /* best-effort perms */
    }
    this.revoked = next;
    this.ver = version;
    this.expiry = expiresAt;
  }

  private static load(path: string): { set: Set<string>; version: number; expiresAt: number | null } {
    // Absent (vs corrupt) file → fresh floor 0. Deleting this file locally resets
    // the anti-rollback floor, but a local attacker with write access to the
    // Grenz home can already edit grenz.yaml or the local revocations directly,
    // so this is outside the threat model. A CORRUPT file, by contrast, throws.
    if (!existsSync(path)) return { set: new Set(), version: 0, expiresAt: null };
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new FleetRevocationError(`fleet-revocations file is not valid JSON: ${path}`);
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new FleetRevocationError(`fleet-revocations file is malformed: ${path}`);
    }
    const o = parsed as Record<string, unknown>;
    if (typeof o.version !== "number" || !Number.isInteger(o.version)) {
      throw new FleetRevocationError(`fleet-revocations file is malformed (version): ${path}`);
    }
    if (!Array.isArray(o.revokedAgents) || !o.revokedAgents.every((a) => typeof a === "string")) {
      throw new FleetRevocationError(`fleet-revocations file is malformed (revokedAgents): ${path}`);
    }
    const expiresAt = o.expiresAt === null || o.expiresAt === undefined ? null : o.expiresAt;
    if (expiresAt !== null && (typeof expiresAt !== "number" || !Number.isInteger(expiresAt))) {
      throw new FleetRevocationError(`fleet-revocations file is malformed (expiresAt): ${path}`);
    }
    return { set: new Set(o.revokedAgents as string[]), version: o.version, expiresAt };
  }
}
