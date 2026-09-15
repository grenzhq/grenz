/**
 * Socket-mode lifecycle.
 *
 * The single-instance guarantee rests on the KERNEL, not on an advisory lock —
 * but NOT on `bind()`. An earlier design assumed `bind()` on a path a live
 * listener owns fails with EADDRINUSE, the way TCP does. Bun does not behave
 * that way: `Bun.serve({ unix })` on an occupied path SUCCEEDS and takes the
 * path over, so the second proxy silently wins and whatever was at the path is
 * replaced. Measured directly on Bun 1.3.11.
 *
 * That makes bind-then-recover unusable: the recovery code never runs, and by
 * the time it would have, the damage is done. So every check happens BEFORE the
 * path is published, and publishing itself is the atomic step:
 *
 *   bind on a private temp path  ->  link(2) it into place
 *
 * `link(2)` fails with EEXIST if anything already holds the name, and it is
 * atomic. That is the mutex — the same kernel guarantee, taken from the
 * primitive that still provides it. The loser of a race never becomes a second
 * listener on a live path; it stops and refuses to start.
 *
 * Why this matters: if two proxies ever serve the same socket, `grenz revoke`
 * mutates only the instance its admin API reaches, while the other keeps
 * injecting real credentials into requests on connections it already accepted.
 *
 * Order:
 *   1. parent directory at 0700 — this, not the socket's own mode, is what
 *      restricts reach (Bun binds the socket 0755 from the umask, and POSIX does
 *      not guarantee connect() honors socket file modes at all)
 *   2. lstat the target FIRST. Anything that is not a socket is refused and
 *      never touched — a mistyped `listen.socket` must not delete the
 *      operator's data. lstat, not stat: a symlink is judged as a symlink
 *   3. if it IS a socket, ask whether its owner is ALIVE (a connect probe).
 *      Live → refuse, never unlink. Dead → stale, and safe to clear
 *   4. bind on a private temp path, then link(2) it into place. EEXIST means
 *      another proxy won the race between 3 and 4 — stop and refuse
 *   5. chmod the socket to 0600
 *
 * Process umask is deliberately untouched: changing it would leak into vault and
 * config file creation elsewhere in the proxy.
 */
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, statSync, unlinkSync } from "node:fs";
import { connect } from "node:net";
import { dirname } from "node:path";

export type PrepareResult = { ok: true } | { ok: false; error: string };
export type BindResult<S> = { ok: true; server: S } | { ok: false; error: string };

/**
 * True when something is listening on `path` right now. Used to tell a live
 * proxy from a socket file left behind by one that exited uncleanly. Local
 * connect only — no egress.
 */
export function isSocketLive(path: string): Promise<boolean> {
  if (!existsSync(path)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const c = connect(path);
    const done = (live: boolean): void => {
      c.destroy();
      resolve(live);
    };
    c.on("connect", () => done(true));
    c.on("error", () => done(false));
  });
}

/** Ensure the socket's parent directory exists and is owner-only. */
export function prepareSocketDir(path: string): PrepareResult {
  const dir = dirname(path);
  try {
    if (!existsSync(dir)) {
      // `mode` is masked by umask, so set it explicitly afterwards too.
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
      return { ok: true };
    }
    const mode = statSync(dir).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      // Never silently chmod a directory the operator configured — refuse and
      // let them decide.
      return {
        ok: false,
        error: `socket directory ${dir} is mode 0o${mode.toString(8)} — group/other access must be off (chmod 700 ${dir})`,
      };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `could not prepare socket directory ${dir}: ${(err as Error).message}` };
  }
}

function errCode(err: unknown): string | undefined {
  return (err as { code?: string } | null)?.code;
}

/** Best-effort stop of a server we are about to abandon. */
function discard<S>(server: S): void {
  const stop = (server as { stop?: (force?: boolean) => void } | null)?.stop;
  if (typeof stop === "function") {
    try {
      stop.call(server, true);
    } catch {
      /* nothing useful to do while unwinding */
    }
  }
}

/** Remove a path we created ourselves; never used on the operator's target. */
function tidy(path: string): void {
  try {
    if (existsSync(path)) unlinkSync(path);
  } catch {
    /* a leftover temp socket in the 0700 run dir is harmless */
  }
}

/**
 * Clear the target path if — and only if — it is a socket whose owner is
 * provably gone. Anything else is refused untouched.
 */
async function clearIfStale(path: string): Promise<PrepareResult> {
  let info;
  try {
    info = lstatSync(path);
  } catch (err) {
    if (errCode(err) === "ENOENT") return { ok: true }; // nothing there — the common case
    return { ok: false, error: `could not inspect ${path}: ${(err as Error).message}` };
  }

  // Not a socket: a mistyped `listen.socket` (say, the request-log filename)
  // resolves inside the Grenz home, and clearing it would destroy the
  // operator's data. lstat, not stat: a symlink is judged as a symlink.
  if (!info.isSocket()) {
    return {
      ok: false,
      error: `${path} exists and is not a socket — refusing to remove it (check listen.socket)`,
    };
  }

  if (await isSocketLive(path)) {
    return { ok: false, error: `another grenz proxy is already running on ${path}` };
  }

  try {
    unlinkSync(path);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `could not remove stale socket ${path}: ${(err as Error).message}` };
  }
}

/**
 * Bind, recovering from a socket file left behind by a proxy that exited
 * uncleanly — but never from one a live proxy still owns.
 *
 * `bind` receives the path to listen on: it is called with a private temp path,
 * which is then published atomically with link(2). Callers must bind exactly
 * where they are told, not where they were configured.
 */
export async function bindWithRecovery<S>(
  path: string,
  bind: (bindPath: string) => S,
): Promise<BindResult<S>> {
  const cleared = await clearIfStale(path);
  if (!cleared.ok) return { ok: false, error: cleared.error };

  // Listen on a name nothing else knows, so an unpublished listener is never
  // reachable. The pid suffix keeps concurrent starts off each other's temp.
  const staging = `${path}.${process.pid}.tmp`;
  const stale = await clearIfStale(staging);
  if (!stale.ok) return { ok: false, error: stale.error };

  let server: S;
  try {
    server = bind(staging);
  } catch (err) {
    tidy(staging);
    return { ok: false, error: `could not listen on ${path}: ${(err as Error).message}` };
  }

  // Publish. link(2) is atomic and fails EEXIST if anything holds the name —
  // this, not bind(), is what stops a second proxy taking over a live socket.
  try {
    linkSync(staging, path);
  } catch (err) {
    discard(server);
    tidy(staging);
    if (errCode(err) === "EEXIST") {
      return { ok: false, error: `another grenz proxy is already running on ${path}` };
    }
    return { ok: false, error: `could not publish socket ${path}: ${(err as Error).message}` };
  }

  // The listener follows the inode, not the name, so dropping the temp name
  // leaves it serving at `path` with exactly one link.
  tidy(staging);
  return { ok: true, server };
}

/** Tighten the bound socket to owner-only. Belt-and-suspenders behind the 0700 dir. */
export function finalizeSocket(path: string): void {
  try {
    chmodSync(path, 0o600);
  } catch {
    /* the 0700 parent directory is the real gate; a chmod failure is not fatal */
  }
}
