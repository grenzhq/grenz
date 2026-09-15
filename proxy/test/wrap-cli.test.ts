import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { runWrap } from "../src/cli/wrap.ts";
import { parseArgs } from "../src/cli/args.ts";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SECRET = "ghp_supersecrettoken1234567890ABCD";

let dir: string;
let out: string;
let err: string;
let restoreOut: () => void;
let restoreErr: () => void;

function capture() {
  out = "";
  err = "";
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = (chunk: string) => {
    out += chunk;
    return true;
  };
  process.stderr.write = (chunk: string) => {
    err += chunk;
    return true;
  };
  restoreOut = () => {
    process.stdout.write = origOut;
  };
  restoreErr = () => {
    process.stderr.write = origErr;
  };
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-wrap-cli-"));
  capture();
});
afterEach(async () => {
  restoreOut();
  restoreErr();
  await rm(dir, { recursive: true, force: true });
});

describe("grenz wrap (advisor CLI)", () => {
  test("a missing config exits 1 with a hint, prints nothing to stdout", async () => {
    const code = await runWrap(parseArgs(["--config", join(dir, "nope.json")]));
    expect(code).toBe(1);
    expect(err).toMatch(/no MCP config/i);
    expect(out).toBe("");
  });

  test("a wrappable config prints the steps and NEVER the secret", async () => {
    const cfg = join(dir, ".mcp.json");
    await writeFile(
      cfg,
      JSON.stringify({
        mcpServers: {
          github: { type: "http", url: "https://api.example.com/mcp", headers: { Authorization: `Bearer ${SECRET}` } },
          local: { type: "stdio", command: "x" },
        },
      }),
    );
    const code = await runWrap(parseArgs(["--config", cfg]));
    expect(code).toBe(0);
    expect(out).toContain("grenz vault set github__authorization");
    expect(out).toContain("http://127.0.0.1:8787/u/github");
    expect(out).toContain("Skipped:");
    expect(out).not.toContain(SECRET);
  });

  test("malformed JSON with a secret near the error exits 1 and does not echo the secret", async () => {
    const cfg = join(dir, ".mcp.json");
    await writeFile(cfg, `{ "mcpServers": { "x": { "headers": { "Authorization": "Bearer ${SECRET}", } } } }`);
    const code = await runWrap(parseArgs(["--config", cfg]));
    expect(code).toBe(1);
    expect(err).not.toContain(SECRET);
    expect(out).toBe("");
  });
});
