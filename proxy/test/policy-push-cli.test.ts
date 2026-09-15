import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPolicyPush } from "../src/cli/policy-push.ts";
import { AgeFileCredentialStore } from "../src/vault/age-file.ts";
import { grenzPaths } from "../src/config/paths.ts";
import { parseArgs, flagString } from "../src/cli/args.ts";
import type { ParsedArgs } from "../src/cli/args.ts";

const TOKEN = "grzp_x";
const URL = "https://cloud.test/api/policy/push";
// Trailing newline is load-bearing: the "verbatim" tests assert it survives
// the file-read/stdin-read -> JSON.stringify({bundle}) round trip untouched.
const BUNDLE_TEXT = '{"version":3,"policy":"agent: a\\non_behalf_of: x\\n","sig":"deadbeef"}\n';

// The real argv tokenizer (parseArgs), exercised end-to-end for the exact
// `--bundle -` (stdin) invocation the usage string documents. A bare "-" was
// previously swallowed as a boolean flag (rejected as "looks like a flag"
// because it starts with "-"), silently breaking `grenz policy push --bundle -`.
describe("real CLI argv -> --bundle -", () => {
  test("`policy push --bundle -` (space-separated) parses bundle as the literal string '-'", () => {
    const args = parseArgs(["policy", "push", "--bundle", "-", "--url", URL, "--token", TOKEN]);
    expect(flagString(args, "bundle")).toBe("-");
    expect(flagString(args, "url")).toBe(URL);
  });

  test("a real flag after a bare '-' is still parsed as a flag, not swallowed as its value", () => {
    const args = parseArgs(["policy", "push", "--bundle", "-", "--url", URL]);
    expect(args.positionals).toEqual(["policy", "push"]);
    expect(flagString(args, "url")).toBe(URL);
  });
});

describe("grenz policy push CLI (runPolicyPush)", () => {
  let tempDirs: string[] = [];
  const originalFetch = globalThis.fetch;
  const originalStdinText = Bun.stdin.text;
  const originalPublishToken = process.env.GRENZ_PUBLISH_TOKEN;

  beforeEach(() => {
    tempDirs = [];
    delete process.env.GRENZ_PUBLISH_TOKEN;
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    Bun.stdin.text = originalStdinText;
    if (originalPublishToken === undefined) delete process.env.GRENZ_PUBLISH_TOKEN;
    else process.env.GRENZ_PUBLISH_TOKEN = originalPublishToken;
    for (const d of tempDirs) await rm(d, { recursive: true, force: true });
  });

  function pushArgs(flags: Record<string, string | boolean>): ParsedArgs {
    return { positionals: ["push"], flags: new Map(Object.entries(flags)) };
  }

  async function captureIO(fn: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
    const out: string[] = [];
    const err: string[] = [];
    const ow = process.stdout.write;
    const ew = process.stderr.write;
    process.stdout.write = ((s: string | Uint8Array) => (out.push(String(s)), true)) as typeof process.stdout.write;
    process.stderr.write = ((s: string | Uint8Array) => (err.push(String(s)), true)) as typeof process.stderr.write;
    try {
      const code = await fn();
      return { code, out: out.join(""), err: err.join("") };
    } finally {
      process.stdout.write = ow;
      process.stderr.write = ew;
    }
  }

  function mockFetch(fn: (url: string, init?: RequestInit) => Promise<Response>): void {
    globalThis.fetch = fn as unknown as typeof fetch;
  }

  /** A fetch stub that fails the test if it's ever invoked -- for the deny-by-default
   * paths (bad token config, missing bundle/url) that must short-circuit before any
   * network call. */
  function unreachableFetch(): void {
    mockFetch(async () => {
      throw new Error("fetch must not be called on this path");
    });
  }

  async function tempBundleFile(text: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "grenz-push-"));
    tempDirs.push(dir);
    const path = join(dir, "bundle.json");
    await writeFile(path, text);
    return path;
  }

  /** CRITICAL charter check: the raw token string must never appear in anything the
   * CLI writes to stdout or stderr, on any path (success, error, or leaked upstream). */
  function expectNoTokenLeak(out: string, err: string, token: string): void {
    expect(out).not.toContain(token);
    expect(err).not.toContain(token);
  }

  test("--bundle <file> --url <u> --token <tok>: verbatim POST + headers; 200 {version:7} -> stdout 'pushed v7', exit 0", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    let seenUrl = "";
    let seenAuth = "";
    let seenContentType = "";
    let seenBody = "";
    mockFetch(async (url, init) => {
      seenUrl = url;
      seenAuth = new Headers(init?.headers).get("authorization") ?? "";
      seenContentType = new Headers(init?.headers).get("content-type") ?? "";
      seenBody = String(init?.body ?? "");
      return new Response(JSON.stringify({ version: 7 }), { status: 200 });
    });

    const { code, out, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, token: TOKEN })),
    );

    expect(code).toBe(0);
    expect(out).toContain("7");
    expect(out).toMatch(/pushed v7/);
    expect(seenUrl).toBe(URL);
    expect(seenAuth).toBe(`Bearer ${TOKEN}`);
    expect(seenContentType).toBe("application/json");
    // Verbatim: the exact bundle bytes (incl. trailing newline) travel unmodified
    // inside {bundle: ...} -- never re-serialized/trimmed/normalized.
    expect(JSON.parse(seenBody)).toEqual({ bundle: BUNDLE_TEXT });
    expect((JSON.parse(seenBody) as { bundle: string }).bundle.endsWith("\n")).toBe(true); // trailing newline preserved
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("--bundle - reads stdin and posts it verbatim", async () => {
    Bun.stdin.text = (async () => BUNDLE_TEXT) as typeof Bun.stdin.text;
    let seenBody = "";
    mockFetch(async (_url, init) => {
      seenBody = String(init?.body ?? "");
      return new Response(JSON.stringify({ version: 9 }), { status: 200 });
    });

    const { code, out, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: "-", url: URL, token: TOKEN })),
    );

    expect(code).toBe(0);
    expect(out).toMatch(/pushed v9/);
    expect(JSON.parse(seenBody)).toEqual({ bundle: BUNDLE_TEXT });
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("GRENZ_PUBLISH_TOKEN env alone works (no --token flag)", async () => {
    process.env.GRENZ_PUBLISH_TOKEN = TOKEN;
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    let seenAuth = "";
    mockFetch(async (_url, init) => {
      seenAuth = new Headers(init?.headers).get("authorization") ?? "";
      return new Response(JSON.stringify({ version: 1 }), { status: 200 });
    });

    const { code, out, err } = await captureIO(() => runPolicyPush(pushArgs({ bundle: bundlePath, url: URL })));

    expect(code).toBe(0);
    expect(seenAuth).toBe(`Bearer ${TOKEN}`);
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("--token-key resolves the token from the age vault (localVault.get, same call run.ts makes)", async () => {
    const home = await mkdtemp(join(tmpdir(), "grenz-push-vault-"));
    tempDirs.push(home);
    const paths = grenzPaths(home);
    const { identity } = await AgeFileCredentialStore.generateIdentity();
    await writeFile(paths.identity, identity);
    const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
    await vault.createEmpty();
    await vault.set("publish-token", TOKEN);

    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    let seenAuth = "";
    mockFetch(async (_url, init) => {
      seenAuth = new Headers(init?.headers).get("authorization") ?? "";
      return new Response(JSON.stringify({ version: 2 }), { status: 200 });
    });

    const { code, out, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, "token-key": "publish-token", home })),
    );

    expect(code).toBe(0);
    expect(seenAuth).toBe(`Bearer ${TOKEN}`);
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("--token-key for a missing vault key -> exit 1, clear error, no network call", async () => {
    const home = await mkdtemp(join(tmpdir(), "grenz-push-vault-missing-"));
    tempDirs.push(home);
    const paths = grenzPaths(home);
    const { identity } = await AgeFileCredentialStore.generateIdentity();
    await writeFile(paths.identity, identity);
    const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
    await vault.createEmpty();
    unreachableFetch();
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);

    const { code, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, "token-key": "nope", home })),
    );

    expect(code).toBe(1);
    expect(err).toMatch(/no credential found/);
  });

  test("--token + GRENZ_PUBLISH_TOKEN together -> exit 1, 'multiple', fetch never called", async () => {
    process.env.GRENZ_PUBLISH_TOKEN = TOKEN;
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    unreachableFetch();

    const { code, out, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, token: TOKEN })),
    );

    expect(code).toBe(1);
    expect(err).toMatch(/multiple/i);
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("no token source given -> exit 1, 'no publish token', fetch never called", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    unreachableFetch();

    const { code, err } = await captureIO(() => runPolicyPush(pushArgs({ bundle: bundlePath, url: URL })));

    expect(code).toBe(1);
    expect(err).toMatch(/no publish token/);
  });

  test("non-2xx (409, 'stale bundle version 3 (active 5)') -> server message to stderr, exit != 0", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    mockFetch(async () => new Response("stale bundle version 3 (active 5)", { status: 409 }));

    const { code, out, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, token: TOKEN })),
    );

    expect(code).not.toBe(0);
    expect(err).toContain("stale bundle version 3 (active 5)");
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("network error -> 'policy source unreachable', exit 1 (same wording as the pull side)", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    mockFetch(async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:1");
    });

    const { code, out, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, token: TOKEN })),
    );

    expect(code).toBe(1);
    expect(err).toMatch(/policy source unreachable/);
    expectNoTokenLeak(out, err, TOKEN);
  });

  test("malformed 2xx response body (not JSON) -> exit 1, clear error", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    mockFetch(async () => new Response("not json", { status: 200 }));

    const { code, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, token: TOKEN })),
    );

    expect(code).toBe(1);
    expect(err).toMatch(/malformed response/);
  });

  test("2xx response missing {version} -> exit 1, clear error", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    mockFetch(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const { code, err } = await captureIO(() =>
      runPolicyPush(pushArgs({ bundle: bundlePath, url: URL, token: TOKEN })),
    );

    expect(code).toBe(1);
    expect(err).toMatch(/malformed response/);
  });

  test("missing --bundle -> usage to stderr, exit 1, fetch never called", async () => {
    unreachableFetch();
    const { code, err } = await captureIO(() => runPolicyPush(pushArgs({ url: URL, token: TOKEN })));
    expect(code).toBe(1);
    expect(err).toMatch(/usage: grenz policy push/);
  });

  test("missing --url -> usage to stderr, exit 1, fetch never called", async () => {
    const bundlePath = await tempBundleFile(BUNDLE_TEXT);
    unreachableFetch();
    const { code, err } = await captureIO(() => runPolicyPush(pushArgs({ bundle: bundlePath, token: TOKEN })));
    expect(code).toBe(1);
    expect(err).toMatch(/usage: grenz policy push/);
  });

  test("bundle file not found -> exit 1, clear error, fetch never called", async () => {
    const dir = await mkdtemp(join(tmpdir(), "grenz-push-"));
    tempDirs.push(dir);
    const missing = join(dir, "does-not-exist.json");
    unreachableFetch();

    const { code, err } = await captureIO(() => runPolicyPush(pushArgs({ bundle: missing, url: URL, token: TOKEN })));

    expect(code).toBe(1);
    expect(err).toMatch(/bundle not found/);
  });
});
