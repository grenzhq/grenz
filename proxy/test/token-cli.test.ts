import { test, expect, describe } from "bun:test";
import { renderTokenList } from "../src/cli/token.ts";

describe("renderTokenList", () => {
  test("renders name / role / status", () => {
    const out = renderTokenList([
      { name: "alice", role: "approver", createdAt: 1000, revokedAt: null },
      { name: "bob", role: "admin", createdAt: 2000, revokedAt: 3000 },
    ]);
    expect(out).toContain("alice");
    expect(out).toContain("approver");
    expect(out).toContain("bob");
    expect(out).toMatch(/revoked/i);
  });
  test("empty -> a friendly line", () => {
    expect(renderTokenList([]).toLowerCase()).toContain("no named");
  });
});
