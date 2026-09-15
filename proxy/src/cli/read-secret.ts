/**
 * Reading a secret from a person or a pipe, without it reaching argv.
 *
 * Shared because `grenz vault set` had no prompt at all: on a terminal it
 * called `Bun.stdin.text()` and blocked with zero output, so the command looked
 * hung rather than waiting for a paste. `grenz connect` grew a prompt first;
 * this is that prompt, moved somewhere both can use it.
 *
 * Never echoes, never returns through a value the caller might log by accident
 * (callers report byte counts). Trailing whitespace and newlines are stripped —
 * `pbpaste` and `echo` both add one, and a token with a trailing newline fails
 * upstream auth in a way that looks like a bad token.
 */

/** Strip what a paste or an `echo` adds, and nothing a secret could need.
 *  Exported for test: a token stored with its trailing newline fails upstream
 *  auth in a way that reads as a bad token. */
export function cleanSecret(raw: string): string {
  return raw.replace(/\s+$/, "");
}

/**
 * Read a secret. Piped stdin is used as-is; on a terminal, `prompt` is written
 * to stderr (so stdout stays clean for piping) and input is read with echo off.
 * Ctrl-C / Ctrl-D returns "" — the caller treats that as "nothing given" and
 * must not store a half-typed secret.
 */
export async function readSecret(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) return cleanSecret(await Bun.stdin.text());

  process.stderr.write(prompt);
  process.stdin.setRawMode?.(true);
  process.stdin.resume();
  let buf = "";
  for await (const chunk of process.stdin) {
    const s = Buffer.from(chunk as Uint8Array).toString("utf8");
    if (s.charCodeAt(0) === 3 || s.charCodeAt(0) === 4) {
      buf = "";
      break;
    }
    const nl = s.search(/[\r\n]/);
    if (nl >= 0) {
      buf += s.slice(0, nl);
      break;
    }
    buf += s;
  }
  process.stdin.setRawMode?.(false);
  process.stdin.pause();
  process.stderr.write("\n");
  return cleanSecret(buf);
}
