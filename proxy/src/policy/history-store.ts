/**
 * Directory-backed policy-version history.
 *
 * Each version of policy.yaml the proxy adopts is written as one plain file in
 * `<home>/policy-history/`. This is OPERATOR CONVENIENCE, not audit or
 * tamper-evidence: files are individually deletable, capped, and carry no
 * integrity guarantee. Unlike the revocation/delegation stores, a missing or
 * unreadable history NEVER blocks the proxy — capture failures are swallowed by
 * the caller. Snapshots hold policy text only, never credential material.
 */
import {
  readdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  unlinkSync,
  mkdirSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";
import {
  snapshotFilename,
  sortSnapshotsNewestFirst,
  snapshotsToPrune,
  shortHash,
  type SnapshotMeta,
} from "./history.ts";

export const MAX_SNAPSHOTS = 50;

export interface Snapshot {
  readonly index: number;
  readonly name: string;
  readonly stamp: string;
  readonly hash: string;
  readonly bytes: number;
}

export class PolicyHistoryStore {
  private readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  private metas(): SnapshotMeta[] {
    if (!existsSync(this.dir)) return [];
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return [];
    }
    return sortSnapshotsNewestFirst(names);
  }

  /** Save `text` as a new snapshot IF it differs from the newest. Prunes to the
   *  cap. Never throws — a capture failure must not break `grenz run`. */
  record(text: string, now: number): { saved: boolean; name: string | null } {
    try {
      if (this.latestHash() === shortHash(text)) return { saved: false, name: null };
      if (!existsSync(this.dir)) mkdirSync(this.dir, { recursive: true });
      const name = snapshotFilename(now, text);
      const tmp = join(this.dir, `.${name}.tmp`);
      writeFileSync(tmp, text);
      renameSync(tmp, join(this.dir, name));
      for (const stale of snapshotsToPrune(this.metas(), MAX_SNAPSHOTS)) {
        try {
          unlinkSync(join(this.dir, stale));
        } catch {
          /* best-effort prune */
        }
      }
      return { saved: true, name };
    } catch {
      return { saved: false, name: null };
    }
  }

  /** Snapshots newest-first, index 1 = most recent. */
  list(): Snapshot[] {
    return this.metas().map((m, i) => {
      let bytes = 0;
      try {
        bytes = readFileSync(join(this.dir, m.name)).byteLength;
      } catch {
        /* leave 0 */
      }
      return { index: i + 1, name: m.name, stamp: m.stamp, hash: m.hash, bytes };
    });
  }

  /** Raw policy text of snapshot #index (1-based), or null if out of range. */
  read(index: number): string | null {
    const m = this.metas()[index - 1];
    if (!m) return null;
    try {
      return readFileSync(join(this.dir, m.name), "utf8");
    } catch {
      return null;
    }
  }

  /** Short hash of the newest snapshot, or null when empty. */
  latestHash(): string | null {
    return this.metas()[0]?.hash ?? null;
  }
}
