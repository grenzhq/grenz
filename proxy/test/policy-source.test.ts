import { test, expect, describe, afterEach } from "bun:test";
import { fetchRemotePolicy } from "../src/policy/source.ts";

const VALID_POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny: [pr:merge]
`;

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function mockFetch(fn: (url: string, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = fn as unknown as typeof fetch;
}

describe("fetchRemotePolicy", () => {
  test("fetches + compiles a valid remote policy; sends the org token", async () => {
    let seenAuth = "";
    mockFetch(async (_url, init) => {
      seenAuth = new Headers(init?.headers).get("authorization") ?? "";
      return new Response(VALID_POLICY, { status: 200 });
    });
    const result = await fetchRemotePolicy("https://cloud.test/api/policy/claude-code", "org_tok");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.policy.agent).toBe("claude-code");
      expect(result.policy.grants.has("github")).toBe(true);
    }
    expect(seenAuth).toBe("Bearer org_tok");
  });

  test("non-2xx status → error (caller falls back to local)", async () => {
    mockFetch(async () => new Response("nope", { status: 403 }));
    const result = await fetchRemotePolicy("https://cloud.test/p", "org_tok");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("403");
  });

  test("network failure → error", async () => {
    mockFetch(async () => {
      throw new Error("unreachable");
    });
    const result = await fetchRemotePolicy("https://cloud.test/p", "org_tok");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unreachable");
  });

  test("malformed remote policy → error (fails closed to local fallback)", async () => {
    mockFetch(async () => new Response("grants: [broken", { status: 200 }));
    const result = await fetchRemotePolicy("https://cloud.test/p", "org_tok");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("malformed policy");
  });
});
