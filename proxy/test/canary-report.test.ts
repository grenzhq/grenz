import { test, expect, describe } from "bun:test";
import { renderCanary } from "../src/cli/policy.ts";

describe("renderCanary", () => {
  test("configured:false -> guidance to start with --canary", () => {
    const out = renderCanary({ configured: false });
    expect(out).toContain("no canary configured");
    expect(out).toContain("--canary");
  });

  test("zero divergences -> clean line", () => {
    const out = renderCanary({ requests: 1204, divergences: 0, rows: [] });
    expect(out).toContain("no divergences");
    expect(out).toContain("1204");
  });

  test("stricter rows listed under a promotion-risk heading; looser under widening", () => {
    const out = renderCanary({
      requests: 1204,
      divergences: 37,
      rows: [
        { tool: "github", action: "issue:list", live: "allow", candidate: "deny", direction: "stricter", count: 18 },
        { tool: "github", action: "repo:read", live: "allow", candidate: "require_approval", direction: "stricter", count: 9 },
        { tool: "linear", action: "comment:delete", live: "deny", candidate: "allow", direction: "looser", count: 10 },
      ],
    });
    expect(out).toContain("37 divergences");
    expect(out).toMatch(/newly BLOCK/i);
    expect(out).toMatch(/newly ALLOW/i);
    expect(out).toContain("github issue:list");
    expect(out).toContain("allow → deny");
    expect(out).toContain("18");
    expect(out).toContain("linear comment:delete");
  });
});
