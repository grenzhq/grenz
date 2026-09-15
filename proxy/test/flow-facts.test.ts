import { test, expect, describe } from "bun:test";
import { FlowFactStore } from "../src/flow/facts.ts";

describe("FlowFactStore", () => {
  test("records and returns facts within the window", () => {
    const s = new FlowFactStore();
    s.record("agentA", "issue:read", "/r/1", 1000);
    s.record("agentA", "file:read", null, 2000);
    expect(s.factsSince("agentA", 1500).map((f) => f.action)).toEqual(["file:read"]);
    expect(s.factsSince("agentA", 0).length).toBe(2);
  });

  test("isolates keys (delegation vs agent)", () => {
    const s = new FlowFactStore();
    s.record("agentA", "issue:read", null, 1000);
    expect(s.factsSince("del-1", 0)).toEqual([]);
  });

  test("caps per-key entries, dropping oldest", () => {
    const s = new FlowFactStore(3); // cap 3
    for (let i = 1; i <= 5; i++) s.record("k", `a:${i}`, null, i * 100);
    const actions = s.factsSince("k", 0).map((f) => f.action);
    expect(actions).toEqual(["a:3", "a:4", "a:5"]);
  });
});
