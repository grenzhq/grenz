import { test, expect, describe } from "bun:test";
import { classifyInvocation, VERSION, type Invocation } from "../src/index.ts";

describe("classifyInvocation", () => {
  const cases: ReadonlyArray<[string[], Invocation]> = [
    [[], "empty"],
    [["version"], "version"],
    [["--version"], "version"],
    [["-v"], "version"],
    [["help"], "help"],
    [["--help"], "help"],
    [["-h"], "help"],
    [["explain", "github", "pr:merge"], "dispatch"],
    [["run", "--help"], "help"], // post-command flag fallback preserved
    [["run", "--version"], "version"], // bare post-command --version still queries the version
    [["--bogus"], "dispatch"], // unknown flag -> unknown-command path
    // `--version <N>` is a VALUE flag for `policy sign` -- it must not be
    // mistaken for the global version query (regression: 7 fell through as a
    // positional and `grenz policy sign ... --version 7` printed the version).
    [["policy", "sign", "p.yaml", "--key", "k", "--version", "7"], "dispatch"],
    // Same footgun for the revocation signer.
    [["revocations", "sign", "--key", "k", "--version", "7"], "dispatch"],
  ];
  for (const [argv, expected] of cases) {
    test(`[${argv.join(" ")}] -> ${expected}`, () => {
      expect(classifyInvocation(argv)).toBe(expected);
    });
  }
});

async function runCli(...cliArgs: string[]): Promise<{ code: number; out: string; err: string }> {
  const proc = Bun.spawn(["bun", "run", "src/index.ts", ...cliArgs], {
    cwd: import.meta.dir + "/..", // proxy/ root
    stdout: "pipe",
    stderr: "pipe",
  });
  const out = await new Response(proc.stdout).text();
  const err = await new Response(proc.stderr).text();
  const code = await proc.exited;
  return { code, out, err };
}

describe("CLI entrypoint (subprocess)", () => {
  test("--version prints version and exits 0", async () => {
    const { code, out } = await runCli("--version");
    expect(out).toContain(`grenz ${VERSION}`);
    expect(code).toBe(0);
  });

  test("--help prints the help banner and exits 0", async () => {
    const { code, out } = await runCli("--help");
    expect(out).toContain("USAGE");
    expect(out).toContain("COMMANDS");
    expect(code).toBe(0);
  });

  // Regression: `grenz --home /x init` answered with `unknown command "--home"`
  // plus the whole banner. --home is listed under COMMON OPTIONS, so putting it
  // first is a reasonable read of the help — the reply has to name the ordering
  // rule and the exact line to retype, not restate the menu.
  test("a leading option names the ordering rule and the command to retype", async () => {
    const { code, out, err } = await runCli("--home", "/tmp/nope", "init");
    expect(err).toContain("options go after the command");
    expect(err).toContain("grenz init --home");
    expect(err).not.toContain("USAGE"); // not the full banner
    expect(out).toBe("");
    expect(code).toBe(1);
  });

  test("a leading option with no command still says what to do", async () => {
    const { code, err } = await runCli("--force");
    expect(err).toContain("grenz <command> --force");
    expect(code).toBe(1);
  });
});
