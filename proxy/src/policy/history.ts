/**
 * Pure helpers for the local policy-version history.
 *
 * This is OPERATOR CONVENIENCE, not audit or tamper-evidence: the short hash
 * below is a NON-CRYPTOGRAPHIC content discriminator (Bun.hash / wyhash), used
 * only to name files and to skip re-saving an identical consecutive version.
 * It is not a signature and provides no integrity guarantee. Snapshots hold
 * policy text only — never credential material.
 */

/** First 8 hex chars of a non-cryptographic content hash. Filename discriminator
 *  + consecutive-duplicate check ONLY — not a security primitive. */
export function shortHash(content: string): string {
  return Bun.hash(content).toString(16).padStart(16, "0").slice(0, 8);
}

/** Compact UTC stamp: 2026-07-15T14:02:00.000Z -> 20260715T140200Z. */
export function compactStamp(now: number): string {
  return new Date(now).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** Snapshot filename for `content` captured at `now`. */
export function snapshotFilename(now: number, content: string): string {
  return `${compactStamp(now)}-${shortHash(content)}.yaml`;
}

export interface SnapshotMeta {
  readonly name: string;
  readonly stamp: string;
  readonly hash: string;
}

const NAME_RE = /^(\d{8}T\d{6}Z)-([0-9a-f]{8})\.yaml$/;

/** Parse a snapshot filename; null if it doesn't match the pattern. */
export function parseSnapshotName(name: string): SnapshotMeta | null {
  const m = NAME_RE.exec(name);
  if (!m) return null;
  return { name, stamp: m[1]!, hash: m[2]! };
}

/** Parse + sort filenames newest-first (by stamp desc, then name desc). Drops
 *  names that don't parse. */
export function sortSnapshotsNewestFirst(names: readonly string[]): SnapshotMeta[] {
  const metas = names.map(parseSnapshotName).filter((m): m is SnapshotMeta => m !== null);
  return metas.sort((a, b) => (a.stamp < b.stamp ? 1 : a.stamp > b.stamp ? -1 : a.name < b.name ? 1 : -1));
}

/** Given snapshots newest-first and a cap, the names to delete (the oldest over
 *  the cap). Empty when at or under the cap. */
export function snapshotsToPrune(newestFirst: readonly SnapshotMeta[], max: number): string[] {
  if (newestFirst.length <= max) return [];
  return newestFirst.slice(max).map((m) => m.name);
}
