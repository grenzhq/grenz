import { test, expect, describe } from "bun:test";
import { parseMcpConfig, planWrap, WrapError, type ListenAddr } from "../src/wrap/plan.ts";

const LISTEN: ListenAddr = { host: "127.0.0.1", port: 8787 };

function plan(servers: Record<string, unknown>) {
  return planWrap(parseMcpConfig(JSON.stringify({ mcpServers: servers })), LISTEN);
}
function one(servers: Record<string, unknown>) {
  const p = plan(servers);
  expect(p.servers).toHaveLength(1);
  return p.servers[0]!;
}

const SECRET = "ghp_supersecrettoken1234567890ABCD";

describe("planWrap — classification", () => {
  test("http server with Authorization: Bearer <literal> is wrappable", () => {
    const s = one({ github: { type: "http", url: "https://api.example.com/mcp", headers: { Authorization: `Bearer ${SECRET}` } } });
    expect(s.action).toBe("wrap");
    if (s.action !== "wrap") return;
    expect(s.header).toBe("Authorization");
    expect(s.scheme).toBe("Bearer");
    expect(s.vaultKey).toBe("github__authorization");
    expect(s.upstream).toBe("github");
    expect(s.url).toBe("https://api.example.com/mcp");
  });

  test("a non-Authorization credential header injects the raw value (empty scheme)", () => {
    const s = one({ svc: { type: "http", url: "https://x/mcp", headers: { "X-API-Key": SECRET } } });
    expect(s.action).toBe("wrap");
    if (s.action !== "wrap") return;
    expect(s.header).toBe("X-API-Key");
    expect(s.scheme).toBe("");
  });

  test("header name match is case-insensitive (lowercase authorization still wraps)", () => {
    const s = one({ svc: { type: "http", url: "https://x/mcp", headers: { authorization: `bearer ${SECRET}` } } });
    expect(s.action).toBe("wrap");
    if (s.action !== "wrap") return;
    expect(s.scheme).toBe("bearer");
  });

  test("a ${VAR} reference is skipped (already externalized)", () => {
    const s = one({ svc: { type: "http", url: "https://x/mcp", headers: { Authorization: "Bearer ${TOKEN}" } } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/externalized/i);
  });

  test("a composite value containing ${...} is treated as a reference, not a literal", () => {
    const s = one({ svc: { type: "http", url: "https://x/mcp", headers: { Authorization: "Bearer ${TOKEN}-suffix" } } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/externalized/i);
  });

  test("stdio server can't be fronted → skip", () => {
    const s = one({ pw: { type: "stdio", command: "npx", args: ["-y", "@x/mcp"], env: { API_KEY: SECRET } } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/stdio/i);
  });

  test("an already-wrapped url (points at the Grenz listener) → skip", () => {
    const s = one({ github: { type: "http", url: "http://127.0.0.1:8787/u/github", headers: { Authorization: "Bearer x" } } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/already wrapped/i);
  });

  test("a url embedding a credential (userinfo) → skip", () => {
    const s = one({ svc: { type: "http", url: `https://user:${SECRET}@host/mcp`, headers: {} } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/url/i);
  });

  test("a url embedding a credential (token query param) → skip", () => {
    const s = one({ svc: { type: "sse", url: `https://host/sse?token=${SECRET}`, headers: {} } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/url/i);
  });

  test("remote server with no credential header → skip (nothing to move)", () => {
    const s = one({ svc: { type: "http", url: "https://x/mcp", headers: { "Content-Type": "application/json" } } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/no credential/i);
  });

  test("two literal credential headers → skip (not representable as one upstream in v1)", () => {
    const s = one({ svc: { type: "http", url: "https://x/mcp", headers: { Authorization: `Bearer ${SECRET}`, "X-API-Key": SECRET } } });
    expect(s.action).toBe("skip");
    if (s.action !== "skip") return;
    expect(s.reason).toMatch(/multiple credential headers/i);
  });

  test("mixed config classifies each server independently", () => {
    const p = plan({
      good: { type: "http", url: "https://a/mcp", headers: { Authorization: `Bearer ${SECRET}` } },
      local: { type: "stdio", command: "x" },
      ref: { type: "http", url: "https://b/mcp", headers: { Authorization: "Bearer ${T}" } },
    });
    expect(p.servers.find((s) => s.name === "good")!.action).toBe("wrap");
    expect(p.servers.find((s) => s.name === "local")!.action).toBe("skip");
    expect(p.servers.find((s) => s.name === "ref")!.action).toBe("skip");
  });
});

describe("parseMcpConfig — no secret leak on error", () => {
  test("a malformed config with a secret adjacent to the syntax error does not echo the secret", () => {
    // trailing comma right after the Authorization line → JSON parse error near the token.
    const bad = `{ "mcpServers": { "x": { "type": "http", "headers": { "Authorization": "Bearer ${SECRET}", } } } }`;
    let msg = "";
    try {
      parseMcpConfig(bad);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(WrapError);
      msg = (e as WrapError).message;
    }
    expect(msg).not.toContain(SECRET);
  });

  test("an empty mcpServers yields an empty plan", () => {
    expect(planWrap(parseMcpConfig(`{"mcpServers":{}}`), LISTEN).servers).toEqual([]);
  });
});
