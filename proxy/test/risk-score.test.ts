import { test, expect, describe } from "bun:test";
import { scoreRisk, type AgentActivity } from "../src/risk/score.ts";

const act = (over: Partial<AgentActivity>): AgentActivity => ({
  total: 0,
  allow: 0,
  deny: 0,
  require_approval: 0,
  distinctDenied: 0,
  ...over,
});

describe("risk scoring", () => {
  test("no activity → low, score 0", () => {
    const r = scoreRisk(act({}));
    expect(r.score).toBe(0);
    expect(r.level).toBe("low");
    expect(r.reasons).toEqual([]);
  });

  test("clean allows → low", () => {
    expect(scoreRisk(act({ total: 20, allow: 20 })).level).toBe("low");
  });

  test("moderate denials → elevated", () => {
    const r = scoreRisk(act({ total: 12, allow: 6, deny: 6, distinctDenied: 1 }));
    expect(r.level).toBe("elevated");
    expect(r.reasons.join(" ")).toContain("denials");
  });

  test("denial spike + probing → high", () => {
    const r = scoreRisk(act({ total: 20, allow: 5, deny: 15, distinctDenied: 4 }));
    expect(r.level).toBe("high");
    expect(r.reasons.join(" ")).toContain("distinct denied");
  });

  test("score is capped at 100", () => {
    expect(scoreRisk(act({ total: 100, deny: 100, distinctDenied: 20 })).score).toBeLessThanOrEqual(100);
  });

  test("high deny RATE counts even at low volume", () => {
    const r = scoreRisk(act({ total: 6, allow: 1, deny: 5, distinctDenied: 2 }));
    expect(r.reasons.join(" ")).toContain("deny rate");
  });

  test("pure — same input, same output", () => {
    const a = act({ total: 12, allow: 6, deny: 6, distinctDenied: 2 });
    expect(scoreRisk(a)).toEqual(scoreRisk(a));
  });
});
