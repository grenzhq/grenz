import { test, expect, describe } from "bun:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  scanFiles,
  renderReport,
  scanExitCode,
  totalSecrets,
} from "../src/scan/scan.ts";
import { candidatePaths, CWD_SURFACES } from "../src/scan/surfaces.ts";
import { runScan } from "../src/cli/scan.ts";
import type { ParsedArgs } from "../src/cli/args.ts";

// One minimal fixture per detector — each string matches exactly one shape.
const CASES: ReadonlyArray<{ detector: string; text: string }> = [
  { detector: "aws_access_key", text: "AKIAIOSFODNN7EXAMPLE" },
  { detector: "github_token", text: "ghp_" + "a".repeat(36) },
  { detector: "github_pat", text: "github_pat_" + "a".repeat(50) },
  { detector: "slack_token", text: "xoxb-0123456789abcdef" },
  { detector: "google_api_key", text: "AIza" + "a".repeat(35) },
  { detector: "stripe_secret_key", text: "sk_live_" + "a".repeat(24) },
  { detector: "openai_key", text: "sk-" + "a".repeat(40) },
  { detector: "private_key", text: "-----BEGIN OPENSSH PRIVATE KEY-----" },
  { detector: "generic_secret_assignment", text: 'password = "supersecretvalue123"' },
];

describe("grenz scan — detectors (table-driven)", () => {
  for (const c of CASES) {
    test(`detects ${c.detector}`, () => {
      const results = scanFiles([{ path: ".env", text: c.text }]);
      expect(results).toHaveLength(1);
      const names = results[0]!.findings.map((f) => f.detector);
      expect(names).toContain(c.detector);
    });
  }

  test("a clean file yields no findings and exit 0", () => {
    const results = scanFiles([{ path: "mcp.json", text: '{"servers":{"x":{"url":"https://ok"}}}' }]);
    expect(results).toHaveLength(0);
    expect(scanExitCode(results)).toBe(0);
  });

  test("findings drive a non-zero exit and a correct total", () => {
    const results = scanFiles([
      { path: ".env", text: "AKIAIOSFODNN7EXAMPLE\nghp_" + "a".repeat(36) },
      { path: ".mcp.json", text: "xoxb-0123456789abcdef" },
    ]);
    expect(scanExitCode(results)).toBe(1);
    expect(totalSecrets(results)).toBe(3);
  });
});

describe("grenz scan — the report never leaks a value", () => {
  const SECRET = "AKIAIOSFODNN7EXAMPLE";

  test("renderReport prints the detector name and count but NOT the secret", () => {
    const results = scanFiles([{ path: ".env", text: `AWS_KEY=${SECRET}` }]);
    const report = renderReport(results, 1);
    expect(report).toContain("aws_access_key");
    expect(report).toContain(".env");
    expect(report).not.toContain(SECRET);
  });

  test("a clean scan reports the check count and a tick", () => {
    const report = renderReport([], 4);
    expect(report).toContain("checked 4 file(s)");
    expect(report).toContain("no plaintext credentials");
  });
});

describe("grenz scan — default surfaces", () => {
  test("candidatePaths covers cwd + home config files", () => {
    const paths = candidatePaths("/work", "/home/me");
    expect(paths).toContain("/work/.env");
    expect(paths).toContain("/work/.mcp.json");
    expect(paths).toContain("/home/me/.claude.json");
    // deny-by-default: a curated list, not a walk of the whole home dir
    expect(paths.length).toBeLessThan(20);
  });

  test("the cwd surface list stays curated", () => {
    expect(CWD_SURFACES).toContain(".env");
    expect(CWD_SURFACES).not.toContain("*");
  });
});

describe("grenz scan — runScan (shell)", () => {
  function args(positionals: string[]): ParsedArgs {
    return { positionals, flags: new Map() };
  }

  test("scans an explicit path, exits 1, prints the detector but never the value", async () => {
    const dir = await mkdtemp(join(tmpdir(), "grenz-scan-"));
    const file = join(dir, "leaky.env");
    const SECRET = "AKIAIOSFODNN7EXAMPLE";
    await writeFile(file, `AWS_ACCESS_KEY_ID=${SECRET}\n`, "utf8");

    const original = process.stdout.write.bind(process.stdout);
    let out = "";
    process.stdout.write = ((chunk: string) => {
      out += chunk;
      return true;
    }) as typeof process.stdout.write;
    let code: number;
    try {
      code = await runScan(args([file]));
    } finally {
      process.stdout.write = original;
    }

    expect(code).toBe(1);
    expect(out).toContain("aws_access_key");
    expect(out).toContain(file);
    expect(out).not.toContain(SECRET);
  });
});
