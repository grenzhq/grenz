import { test, expect, describe } from "bun:test";
import {
  approvalIdleTimeout,
  approvalHoldNote,
  BUN_IDLE_MAX_SECONDS,
  IDLE_BUFFER_SECONDS,
} from "../src/proxy/server.ts";

describe("approvalIdleTimeout", () => {
  const cases: ReadonlyArray<[number, number, boolean]> = [
    // [ttlSeconds, idleTimeout, capped]
    [300, 255, true], // default TTL clamps to ceiling
    [60, 65, false], // under ceiling, buffer applied
    [250, 255, false], // 250+5 = 255 exactly at ceiling, not over
    [251, 255, true], // 251+5 = 256 > 255, capped
    [255, 255, true], // 255+5 > 255, capped
    [3600, 255, true], // max TTL clamps to ceiling
    [1, 6, false], // tiny TTL, buffer applied
  ];
  for (const [ttl, idleTimeout, capped] of cases) {
    test(`ttl ${ttl}s -> idleTimeout ${idleTimeout}s, capped ${capped}`, () => {
      const plan = approvalIdleTimeout(ttl);
      expect(plan.idleTimeout).toBe(idleTimeout);
      expect(plan.capped).toBe(capped);
    });
  }

  test("constants are the documented Bun ceiling and buffer", () => {
    expect(BUN_IDLE_MAX_SECONDS).toBe(255);
    expect(IDLE_BUFFER_SECONDS).toBe(5);
  });
});

describe("approvalHoldNote (banner inline note, not a pre-banner alarm)", () => {
  test("capped TTL (300s default) gets an in-context hold note", () => {
    const note = approvalHoldNote(300);
    expect(note).toContain(`≤${BUN_IDLE_MAX_SECONDS}s`);
    expect(note).toContain("the agent retries");
    // A note, never an alarm: it's a parenthetical suffix, not a standalone line.
    expect(note.startsWith(" (")).toBe(true);
  });

  test("under-ceiling TTL (60s) adds no note — the common case stays quiet", () => {
    expect(approvalHoldNote(60)).toBe("");
  });

  test("exactly-at-ceiling TTL (250s) adds no note", () => {
    expect(approvalHoldNote(250)).toBe("");
  });
});
