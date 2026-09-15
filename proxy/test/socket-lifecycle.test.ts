import { test, expect, describe, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { existsSync, lstatSync, mkdirSync, statSync, writeFileSync, chmodSync, readFileSync, symlinkSync } from "node:fs";
import { prepareSocketDir, bindWithRecovery, finalizeSocket, isSocketLive } from "../src/run/socket.ts";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-sock-life-"));
});

// bindWithRecovery calls this with the path it wants listened on (a private
// staging name), not the final one — bind exactly where told.
const serve = (body = "mine") => (bindPath: string) =>
  Bun.serve({ unix: bindPath, fetch: () => new Response(body) });

describe("prepareSocketDir", () => {
  test("creates a missing parent directory at 0700", () => {
    const sock = join(dir, "run", "agent.sock");
    expect(prepareSocketDir(sock)).toEqual({ ok: true });
    expect((statSync(dirname(sock)).mode & 0o777).toString(8)).toBe("700");
  });

  test("a directory with group/other access refuses startup", () => {
    const parent = join(dir, "loose");
    mkdirSync(parent, { recursive: true });
    chmodSync(parent, 0o755);
    const r = prepareSocketDir(join(parent, "agent.sock"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/group\/other|chmod 700/i);
  });

  test("a pre-existing 0700 directory is accepted and never silently chmod'd", () => {
    const parent = join(dir, "tight");
    mkdirSync(parent, { recursive: true });
    chmodSync(parent, 0o700);
    expect(prepareSocketDir(join(parent, "agent.sock"))).toEqual({ ok: true });
    expect((statSync(parent).mode & 0o777).toString(8)).toBe("700");
  });

  test("an unusable directory path returns an error rather than throwing", () => {
    const notADir = join(dir, "file");
    writeFileSync(notADir, "x");
    const r = prepareSocketDir(join(notADir, "nested", "a.sock"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/could not prepare/i);
  });
});

describe("bindWithRecovery", () => {
  test("a free path binds on the first attempt", async () => {
    const sock = join(dir, "fresh.sock");
    const r = await bindWithRecovery(sock, serve());
    expect(r.ok).toBe(true);
    if (r.ok) r.server.stop(true);
  });

  test("a LIVE socket is refused and NEVER unlinked (the ghost-proxy invariant)", async () => {
    const sock = join(dir, "live.sock");
    const original = Bun.serve({ unix: sock, fetch: () => new Response("original") });

    const r = await bindWithRecovery(sock, serve());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/already running/i);
    expect(existsSync(sock)).toBe(true); // the file survived
    // …and the original proxy is still serving. No ghost, no takeover.
    expect(await (await fetch("http://localhost/", { unix: sock })).text()).toBe("original");
    original.stop(true);
  });

  test("a STALE socket is cleared and the bind succeeds", async () => {
    const sock = join(dir, "stale.sock");
    // Simulate a crashed proxy: bind in a child, SIGKILL so cleanup never runs.
    const child = Bun.spawn(
      ["bun", "-e", `Bun.serve({ unix: ${JSON.stringify(sock)}, fetch: () => new Response("x") }); await new Promise(() => {});`],
      { stdout: "ignore", stderr: "ignore" },
    );
    await Bun.sleep(500);
    child.kill("SIGKILL");
    await child.exited;
    await Bun.sleep(200);
    expect(existsSync(sock)).toBe(true);
    expect(await isSocketLive(sock)).toBe(false);

    const r = await bindWithRecovery(sock, serve());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(await (await fetch("http://localhost/", { unix: sock })).text()).toBe("mine");
      r.server.stop(true);
    }
  }, 15_000);

  test("a REGULAR FILE at the socket path is never deleted (a mistyped listen.socket must not destroy data)", async () => {
    const notASocket = join(dir, "requests.db");
    writeFileSync(notASocket, "PRECIOUS REQUEST LOG DATA");
    const r = await bindWithRecovery(notASocket, serve());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/not a socket/i);
    expect(existsSync(notASocket)).toBe(true);
    expect(readFileSync(notASocket, "utf8")).toBe("PRECIOUS REQUEST LOG DATA");
  });

  test("a SYMLINK at the socket path is judged as a symlink, not its target", async () => {
    const target = join(dir, "target.db");
    const link = join(dir, "link.sock");
    writeFileSync(target, "DATA");
    symlinkSync(target, link);
    const r = await bindWithRecovery(link, serve());
    expect(r.ok).toBe(false);
    expect(existsSync(target)).toBe(true);
    expect(readFileSync(target, "utf8")).toBe("DATA");
  });

  // Bun's `Bun.serve({ unix })` does NOT raise EADDRINUSE on an occupied path —
  // it takes the path over. So the liveness probe alone cannot decide a race:
  // two starts can both pass it before either publishes. link(2) is what makes
  // exactly one of them win.
  test("CONCURRENT starts: exactly one wins, and the loser is not a second listener", async () => {
    const sock = join(dir, "race.sock");
    const results = await Promise.all([
      bindWithRecovery(sock, serve("A")),
      bindWithRecovery(sock, serve("B")),
      bindWithRecovery(sock, serve("C")),
    ]);

    const winners = results.filter((r) => r.ok);
    expect(winners.length).toBe(1);
    for (const loser of results.filter((r) => !r.ok)) {
      if (!loser.ok) expect(loser.error).toMatch(/already running/i);
    }

    // The published socket answers as the single winner, consistently.
    const body = await (await fetch("http://localhost/", { unix: sock })).text();
    expect(await (await fetch("http://localhost/", { unix: sock })).text()).toBe(body);
    for (const r of winners) if (r.ok) r.server.stop(true);
  });

  test("the staging socket is not left behind on success", async () => {
    const sock = join(dir, "clean.sock");
    const r = await bindWithRecovery(sock, serve());
    expect(r.ok).toBe(true);
    expect(existsSync(`${sock}.${process.pid}.tmp`)).toBe(false);
    expect(lstatSync(sock).isSocket()).toBe(true);
    if (r.ok) r.server.stop(true);
  });
});

describe("isSocketLive", () => {
  test("true for a live socket, false for a missing path", async () => {
    const sock = join(dir, "probe.sock");
    expect(await isSocketLive(sock)).toBe(false);
    const s = Bun.serve({ unix: sock, fetch: () => new Response("x") });
    expect(await isSocketLive(sock)).toBe(true);
    s.stop(true);
  });
});

describe("finalizeSocket", () => {
  test("tightens the bound socket to 0600 (Bun binds it 0755 from the umask)", async () => {
    const sock = join(dir, "perm.sock");
    const r = await bindWithRecovery(sock, serve());
    expect(r.ok).toBe(true);
    finalizeSocket(sock);
    expect((statSync(sock).mode & 0o777).toString(8)).toBe("600");
    expect((await fetch("http://localhost/", { unix: sock })).status).toBe(200);
    if (r.ok) r.server.stop(true);
  });

  test("a missing socket does not throw (the 0700 dir is the real gate)", () => {
    expect(() => finalizeSocket(join(dir, "nope.sock"))).not.toThrow();
  });
});
