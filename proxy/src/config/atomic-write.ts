/**
 * Durable, race-aware atomic write for grenz.yaml. Beyond tmp+rename, it:
 *   - uses a UNIQUE temp name (pid + random) so two writers never share a temp
 *     file and rename a torn/foreign one into place;
 *   - fsyncs the temp file before rename, so a "201, it survives restart"
 *     contract holds through a power loss;
 *   - re-reads the target just before rename and aborts if it no longer matches
 *     the content the caller based its rewrite on (a concurrent `grenz rotate`
 *     or `grenz decoy` from another process) — last-writer-wins would otherwise
 *     silently drop that change and mint a token that dies at next restart.
 */
import { openSync, writeSync, fsyncSync, closeSync, renameSync, readFileSync, unlinkSync } from "node:fs";

export class ConfigChangedError extends Error {
  constructor() {
    super("grenz.yaml changed on disk during the write");
    this.name = "ConfigChangedError";
  }
}

/**
 * Write `contents` to `path` atomically and durably. `expectedBase` is the exact
 * text the rewrite was derived from; if the file differs at rename time, throws
 * ConfigChangedError and leaves the target untouched.
 */
export function writeConfigAtomic(path: string, contents: string, expectedBase: string): void {
  const tmp = `${path}.tmp.${process.pid}.${crypto.randomUUID()}`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, contents);
    fsyncSync(fd); // durability: the bytes are on disk before the rename publishes them
  } finally {
    closeSync(fd);
  }
  try {
    // TOCTOU guard against another process: the base we rewrote must still be
    // what's on disk, or we'd clobber a concurrent rotate/decoy.
    const current = readFileSync(path, "utf8");
    if (current !== expectedBase) {
      unlinkSync(tmp);
      throw new ConfigChangedError();
    }
    renameSync(tmp, path);
  } catch (err) {
    if (!(err instanceof ConfigChangedError)) {
      // Best-effort cleanup of the temp on any rename/read failure.
      try {
        unlinkSync(tmp);
      } catch {
        /* already gone */
      }
    }
    throw err;
  }
}
