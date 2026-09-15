import { test, expect, describe } from "bun:test";
import { renderWindows } from "../src/cli/break-glass.ts";

describe("renderWindows", () => {
  test("renders agent / actions / quorum / puller", () => {
    const out = renderWindows([
      { id: "bg_1", agent: "claude", actions: ["pr:merge"], quorum: 1, reason: "hotfix", pulled_by: "carol", expires_at: 1_800_000_000_000 },
    ]);
    expect(out).toContain("bg_1");
    expect(out).toContain("claude");
    expect(out).toContain("pr:merge");
    expect(out).toContain("carol");
    expect(out).toContain("hotfix");
  });
  test("empty -> a friendly line", () => {
    expect(renderWindows([]).toLowerCase()).toContain("no active break-glass");
  });
});
