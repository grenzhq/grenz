/**
 * `grenz init` must keep the home's secrets out of version control, and warn
 * when the home sits inside a git worktree the agent can read.
 *
 * The home holds the age identity, the encrypted vault, and the admin token.
 * A committed home leaks the real credential; a home inside the agent's own
 * worktree is readable by the very agent it firewalls. init defends both:
 *   - always writes a .gitignore that ignores everything except the shareable
 *     grenz.yaml + policy.yaml (no secret values),
 *   - prints a loud stderr warning when the home is inside a git repo.
 */
import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { runInit, homeGitignore, repoContainingHome } from "../src/cli/init.ts";
import { parseArgs } from "../src/cli/args.ts";
import { grenzPaths } from "../src/config/paths.ts";

let tmp: string;
let stdoutBuf: string;
let stderrBuf: string;
let origOut: typeof process.stdout.write;
let origErr: typeof process.stderr.write;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-init-"));
  stdoutBuf = "";
  stderrBuf = "";
  origOut = process.stdout.write;
  origErr = process.stderr.write;
  process.stdout.write = ((chunk: string) => {
    stdoutBuf += chunk;
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string) => {
    stderrBuf += chunk;
    return true;
  }) as typeof process.stderr.write;
});

afterEach(async () => {
  process.stdout.write = origOut;
  process.stderr.write = origErr;
  await rm(tmp, { recursive: true, force: true });
});

describe("grenz init — .gitignore", () => {
  test("writes a .gitignore into the home", async () => {
    const home = join(tmp, ".grenz");
    const code = await runInit(parseArgs(["--home", home]));
    expect(code).toBe(0);
    expect(existsSync(grenzPaths(home).gitignore)).toBe(true);
  });

  test("ignores the secrets but un-ignores the shareable config", () => {
    const gi = homeGitignore();
    expect(gi).toContain("*");
    expect(gi).toContain("!grenz.yaml");
    expect(gi).toContain("!policy.yaml");
    // secrets must never be un-ignored
    expect(gi).not.toContain("!identity");
    expect(gi).not.toContain("!vault.age");
    expect(gi).not.toContain("!admin.token");
  });

  test("git actually ignores the vault + keys, tracks the policy", async () => {
    // real git semantics — the guarantee that matters
    const repo = join(tmp, "repo");
    await mkdir(repo, { recursive: true });
    const git = (...a: string[]) => spawnSync("git", ["-C", repo, ...a], { encoding: "utf8" });
    if (git("init").status !== 0) return; // git unavailable — skip the functional check
    const home = join(repo, ".grenz");
    await runInit(parseArgs(["--home", home]));

    const ignored = (rel: string) => git("check-ignore", join(home, rel)).status === 0;
    expect(ignored("identity")).toBe(true);
    expect(ignored("vault.age")).toBe(true);
    expect(ignored("admin.token")).toBe(true);
    expect(ignored("requests.db")).toBe(true);
    // the shareable, secret-free files stay tracked
    expect(ignored("grenz.yaml")).toBe(false);
    expect(ignored("policy.yaml")).toBe(false);
  });

  test("a pre-existing .gitignore is not clobbered on --force re-init", async () => {
    const home = join(tmp, ".grenz");
    await runInit(parseArgs(["--home", home]));
    const custom = "# my custom ignores\nnode_modules/\n";
    await writeFile(grenzPaths(home).gitignore, custom);
    await runInit(parseArgs(["--home", home, "--force"]));
    expect(await Bun.file(grenzPaths(home).gitignore).text()).toBe(custom);
  });
});

describe("grenz init — worktree warning", () => {
  test("repoContainingHome finds the enclosing repo", async () => {
    const repo = join(tmp, "proj");
    await mkdir(join(repo, ".git"), { recursive: true });
    const home = join(repo, ".grenz");
    expect(repoContainingHome(home)).toBe(repo);
  });

  test("repoContainingHome returns null outside any repo", () => {
    // tmp is a fresh mkdtemp dir with no .git anywhere under it
    expect(repoContainingHome(join(tmp, ".grenz"))).toBeNull();
  });

  test("warns on stderr when the home is inside a git repo", async () => {
    const repo = join(tmp, "proj");
    await mkdir(join(repo, ".git"), { recursive: true });
    const home = join(repo, ".grenz");
    await runInit(parseArgs(["--home", home]));
    expect(stderrBuf).toContain("inside a git repository");
    expect(stderrBuf).toContain("GRENZ_HOME");
  });

  test("does NOT warn when the home is outside any repo", async () => {
    const home = join(tmp, ".grenz");
    await runInit(parseArgs(["--home", home]));
    expect(stderrBuf).not.toContain("inside a git repository");
  });
});
