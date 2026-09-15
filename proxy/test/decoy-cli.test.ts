import { test, expect, describe, beforeEach } from "bun:test";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDecoy } from "../src/cli/decoy.ts";
import { parseArgs } from "../src/cli/args.ts";
import { configSchema } from "../src/config/schema.ts";
import { parse } from "yaml";

let home: string;

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "grenz-decoycli-"));
  const cfg = `agents:
  - id: real
    token_hash: ${"a".repeat(64)}
upstreams:
  github:
    type: github
    base_url: https://api.github.com
    credential: github_token
`;
  await writeFile(join(home, "grenz.yaml"), cfg);
});

function args(argv: string[]) {
  return parseArgs([...argv, "--home", home]);
}

describe("grenz decoy CLI", () => {
  test("decoy token <name> appends a valid decoy agent", async () => {
    const code = await runDecoy(args(["token", "trap"]));
    expect(code).toBe(0);
    const raw = await readFile(join(home, "grenz.yaml"), "utf8");
    const cfg = configSchema.parse(parse(raw)); // still valid
    expect(cfg.agents.find((a) => a.id === "trap")).toMatchObject({ decoy: true });
  });

  test("decoy upstream <name> appends a valid decoy upstream", async () => {
    const code = await runDecoy(args(["upstream", "honeypot"]));
    expect(code).toBe(0);
    const raw = await readFile(join(home, "grenz.yaml"), "utf8");
    const cfg = configSchema.parse(parse(raw));
    expect(cfg.upstreams.honeypot).toEqual({ decoy: true, type: "mcp" });
  });

  test("decoy token refuses a colliding id (nonzero, config untouched)", async () => {
    const before = await readFile(join(home, "grenz.yaml"), "utf8");
    const code = await runDecoy(args(["token", "real"]));
    expect(code).toBe(1);
    expect(await readFile(join(home, "grenz.yaml"), "utf8")).toBe(before);
  });

  test("decoy remove deletes a decoy but refuses a real agent", async () => {
    await runDecoy(args(["token", "trap"]));
    expect(await runDecoy(args(["remove", "trap"]))).toBe(0);
    // 'real' is a real agent, not a decoy → refuse
    expect(await runDecoy(args(["remove", "real"]))).toBe(1);
  });

  test("decoy list shows planted decoys as armed (offline, no admin token)", async () => {
    await runDecoy(args(["token", "trap"]));
    await runDecoy(args(["upstream", "honeypot"]));
    const chunks: string[] = [];
    const orig = process.stdout.write.bind(process.stdout);
    (process.stdout.write as unknown as (s: string) => boolean) = (s: string) => {
      chunks.push(s);
      return true;
    };
    let code: number;
    try {
      code = await runDecoy(args(["list"]));
    } finally {
      process.stdout.write = orig;
    }
    const out = chunks.join("");
    expect(code).toBe(0);
    expect(out).toContain("decoy tokens (1)");
    expect(out).toContain("trap");
    expect(out).toContain("armed");
    expect(out).toContain("decoy upstreams (1)");
    expect(out).toContain("honeypot");
  });
});
