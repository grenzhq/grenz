/**
 * Pure resolution + validation of `listen.socket`. Kept separate from the socket
 * lifecycle so `grenz doctor` can check a configured path without binding
 * anything.
 *
 * The bound is the platform's `sun_path` limit (~104 bytes on macOS, 108 on
 * Linux, including the terminator). Exceeding it fails at bind with
 * ENAMETOOLONG; we would rather refuse at load with remediation text.
 */
import { isAbsolute, resolve } from "node:path";

/** Smallest `sun_path` across supported platforms, less the NUL terminator. */
export const SUN_PATH_MAX = 103;

/**
 * Bytes held back for the staging name the socket is bound to before being
 * published atomically (see `run/socket.ts`): `.` + pid + `.tmp`, where Linux
 * allows a pid up to 7 digits. The staging path is what actually reaches
 * bind(), so the configured path must leave room for it or a path that
 * validates here would fail at bind with ENAMETOOLONG.
 */
export const STAGING_RESERVE = 12;

export const MAX_SOCKET_PATH = SUN_PATH_MAX - STAGING_RESERVE;

export type SocketPathResult = { ok: true; path: string } | { ok: false; error: string };

export function resolveSocketPath(configured: string, home: string): SocketPathResult {
  // A leading NUL binds a Linux ABSTRACT-namespace socket: no file, no mode
  // bits, no parent directory — every path-based defense silently stops
  // applying while the banner still reports socket mode. Rejected here as well
  // as in the schema, since this resolver is the last gate before bind.
  if (configured.includes("\0")) {
    return { ok: false, error: "listen.socket must not contain a NUL byte" };
  }
  const path = isAbsolute(configured) ? configured : resolve(home, configured);
  if (!isAbsolute(path)) {
    return { ok: false, error: `listen.socket must resolve to an absolute path (got "${path}")` };
  }
  // The kernel limit is in BYTES; a multibyte path is shorter in characters.
  const bytes = Buffer.byteLength(path, "utf8");
  if (bytes > MAX_SOCKET_PATH) {
    return {
      ok: false,
      error: `listen.socket path is too long (${bytes} bytes, max ${MAX_SOCKET_PATH}) — set a shorter listen.socket or a shorter --home`,
    };
  }
  return { ok: true, path };
}
