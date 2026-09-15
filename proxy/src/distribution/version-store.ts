/**
 * Persists the last-accepted signed-policy version as the anti-rollback floor,
 * so a proxy restart cannot be tricked into accepting a replayed older policy.
 * Plain JSON (0600), throw-on-corrupt (fail-closed) — operational state, not an
 * audit record.
 */
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync } from "node:fs";

export class PolicyVersionStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyVersionStoreError";
  }
}

export class PolicyVersionStore {
  private readonly path: string;
  private version: number;

  constructor(path: string) {
    this.path = path;
    this.version = PolicyVersionStore.load(path);
  }

  private static load(path: string): number {
    if (!existsSync(path)) return 0;
    let parsed: { version?: unknown };
    try {
      parsed = JSON.parse(readFileSync(path, "utf8")) as { version?: unknown };
    } catch (err) {
      throw new PolicyVersionStoreError(
        `corrupt policy-version file at ${path}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (typeof parsed.version !== "number" || !Number.isInteger(parsed.version)) {
      throw new PolicyVersionStoreError(`malformed policy-version file at ${path}`);
    }
    return parsed.version;
  }

  floor(): number {
    return this.version;
  }

  accept(version: number, _now: number): void {
    if (version <= this.version) return;
    this.version = version;
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ version }, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
    try {
      chmodSync(this.path, 0o600);
    } catch {
      /* best-effort perms */
    }
  }
}
