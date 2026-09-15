import { test, expect, describe } from "bun:test";
import { PinStore } from "../src/pin/store.ts";

describe("PinStore", () => {
  test("records and reads back facts for a key", () => {
    const s = new PinStore();
    s.record("agent-a", 0, "acme/api", 1000);
    s.record("agent-a", 0, "acme/payroll", 2000);
    expect(s.factsSince("agent-a", 0)).toEqual([
      { ruleIndex: 0, unit: "acme/api", ts: 1000 },
      { ruleIndex: 0, unit: "acme/payroll", ts: 2000 },
    ]);
  });

  test("factsSince filters by window and is a pure non-mutating read", () => {
    const s = new PinStore();
    s.record("k", 0, "a", 1000);
    s.record("k", 0, "b", 5000);
    expect(s.factsSince("k", 4000).map((f) => f.unit)).toEqual(["b"]);
    // wider query still sees the older fact (not discarded by the narrow read)
    expect(s.factsSince("k", 0).map((f) => f.unit)).toEqual(["a", "b"]);
  });

  test("unknown key -> empty", () => {
    expect(new PinStore().factsSince("nope", 0)).toEqual([]);
  });

  test("per-key cap bounds memory (oldest dropped)", () => {
    const s = new PinStore(2);
    s.record("k", 0, "a", 1);
    s.record("k", 0, "b", 2);
    s.record("k", 0, "c", 3);
    expect(s.factsSince("k", 0).map((f) => f.unit)).toEqual(["b", "c"]);
  });
});
