import { test, expect, describe } from "bun:test";
import { parseMcpConfig, planWrap, type ListenAddr } from "../src/wrap/plan.ts";
import { renderAdvisor } from "../src/wrap/render.ts";

const LISTEN: ListenAddr = { host: "127.0.0.1", port: 8787 };
const SECRET = "ghp_supersecrettoken1234567890ABCD";

function render(servers: Record<string, unknown>) {
  const plan = planWrap(parseMcpConfig(JSON.stringify({ mcpServers: servers })), LISTEN);
  return renderAdvisor(plan, { listen: LISTEN, configPath: ".mcp.json" });
}

describe("renderAdvisor", () => {
  const out = render({
    github: { type: "http", url: "https://api.example.com/mcp", headers: { Authorization: `Bearer ${SECRET}` } },
  });

  test("NEVER prints the secret value", () => {
    expect(out).not.toContain(SECRET);
  });

  test("emits the four apply steps with the right identifiers", () => {
    expect(out).toContain("grenz vault set github__authorization");
    expect(out).toContain("base_url: https://api.example.com/mcp");
    expect(out).toContain("credential: github__authorization");
    expect(out).toContain("http://127.0.0.1:8787/u/github");
    expect(out).toContain('"Bearer <YOUR_GRENZ_TOKEN>"');
    expect(out).toContain("tool: github");
  });

  test("the vault command strips the Bearer scheme so only the token is stored", () => {
    expect(out).toContain('sub("^Bearer ";"")');
  });

  test("a raw-value header (no scheme) stores the value verbatim", () => {
    const o = render({ svc: { type: "http", url: "https://x/mcp", headers: { "X-API-Key": SECRET } } });
    expect(o).not.toContain(SECRET);
    expect(o).not.toContain("sub(");
    expect(o).toContain("grenz vault set svc__x_api_key");
    expect(o).toContain('"<YOUR_GRENZ_TOKEN>"'); // no scheme prefix
  });

  test("skipped servers are listed with reasons", () => {
    const o = render({
      good: { type: "http", url: "https://a/mcp", headers: { Authorization: `Bearer ${SECRET}` } },
      local: { type: "stdio", command: "x" },
    });
    expect(o).toContain("Skipped:");
    expect(o).toContain("local —");
    expect(o).toMatch(/stdio/i);
  });

  test("nothing-to-wrap config says so and leaks nothing", () => {
    const o = render({ local: { type: "stdio", command: "x", env: { API_KEY: SECRET } } });
    expect(o).toContain("No servers to wrap.");
    expect(o).not.toContain(SECRET);
  });
});
