import { test, expect, describe } from "bun:test";
import { CanaryStore } from "../src/canary/store.ts";

describe("CanaryStore", () => {
  test("identical verdicts count a request but no divergence", () => {
    const s = new CanaryStore();
    s.observe("github", "repo:read", "allow", "allow");
    const snap = s.snapshot();
    expect(snap.requests).toBe(1);
    expect(snap.divergences).toBe(0);
    expect(snap.rows).toEqual([]);
  });

  test("candidate stricter -> a stricter row (allow -> deny)", () => {
    const s = new CanaryStore();
    s.observe("github", "issue:list", "allow", "deny");
    const snap = s.snapshot();
    expect(snap.requests).toBe(1);
    expect(snap.divergences).toBe(1);
    expect(snap.rows).toEqual([
      { tool: "github", action: "issue:list", live: "allow", candidate: "deny", direction: "stricter", count: 1 },
    ]);
  });

  test("classifies stricter vs looser by permissiveness allow<require_approval<deny", () => {
    const s = new CanaryStore();
    s.observe("github", "a", "allow", "require_approval"); // stricter
    s.observe("github", "b", "require_approval", "deny"); // stricter
    s.observe("linear", "c", "deny", "allow"); // looser
    s.observe("linear", "d", "require_approval", "allow"); // looser
    const dir = (action: string) => s.snapshot().rows.find((r) => r.action === action)!.direction;
    expect(dir("a")).toBe("stricter");
    expect(dir("b")).toBe("stricter");
    expect(dir("c")).toBe("looser");
    expect(dir("d")).toBe("looser");
  });

  test("repeated identical divergence aggregates the count", () => {
    const s = new CanaryStore();
    s.observe("github", "issue:list", "allow", "deny");
    s.observe("github", "issue:list", "allow", "deny");
    s.observe("github", "issue:list", "allow", "deny");
    const row = s.snapshot().rows.find((r) => r.action === "issue:list")!;
    expect(row.count).toBe(3);
    expect(s.snapshot().divergences).toBe(3);
    expect(s.snapshot().requests).toBe(3);
  });

  test("snapshot ordering: stricter before looser, then count desc, then tool/action", () => {
    const s = new CanaryStore();
    s.observe("linear", "z", "deny", "allow"); // looser, count 1
    s.observe("github", "a", "allow", "deny"); // stricter, count 1
    s.observe("github", "b", "allow", "deny"); // stricter, count 2
    s.observe("github", "b", "allow", "deny");
    const rows = s.snapshot().rows;
    expect(rows.map((r) => r.action)).toEqual(["b", "a", "z"]);
  });
});
