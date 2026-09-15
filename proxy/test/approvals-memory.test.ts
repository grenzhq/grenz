import { test, expect, describe } from "bun:test";
import { ApprovalMemory, MAX_ENTRIES, type MemoryKeyInput } from "../src/approvals/memory.ts";
import { approvalsSchema } from "../src/config/schema.ts";

const KEY: MemoryKeyInput = {
  agentId: "claude-code",
  tool: "github",
  action: "issue:update",
  target: "/repos/o/r/issues/5",
};

describe("ApprovalMemory", () => {
  test("remember + recall both outcomes; absent key misses", () => {
    const t = 1000;
    const m = new ApprovalMemory(10_000, () => t);
    expect(m.recall(KEY)).toBeNull();
    m.remember(KEY, "approved");
    expect(m.recall(KEY)).toBe("approved");
    m.remember(KEY, "denied"); // latest decision wins
    expect(m.recall(KEY)).toBe("denied");
  });

  test("exact-key scoping: any differing field misses", () => {
    const t = 1000;
    const m = new ApprovalMemory(10_000, () => t);
    m.remember(KEY, "approved");
    expect(m.recall({ ...KEY, target: "/repos/o/r/issues/6" })).toBeNull();
    expect(m.recall({ ...KEY, action: "issue:read" })).toBeNull();
    expect(m.recall({ ...KEY, agentId: "ci-bot" })).toBeNull();
    expect(m.recall({ ...KEY, tool: "linear" })).toBeNull();
  });

  test("expires after the window and the entry is swept", () => {
    let t = 1000;
    const m = new ApprovalMemory(1_000, () => t);
    m.remember(KEY, "approved");
    t = 1999;
    expect(m.recall(KEY)).toBe("approved");
    t = 2000; // expiresAt reached
    expect(m.recall(KEY)).toBeNull();
    expect(m.size()).toBe(0); // swept
  });

  test("re-remember refreshes the window", () => {
    let t = 1000;
    const m = new ApprovalMemory(1_000, () => t);
    m.remember(KEY, "approved");
    t = 1900;
    m.remember(KEY, "approved"); // refresh
    t = 2500; // past the original expiry, inside the refreshed one
    expect(m.recall(KEY)).toBe("approved");
  });

  test("clear() drops everything", () => {
    const m = new ApprovalMemory(10_000, () => 0);
    m.remember(KEY, "approved");
    m.clear();
    expect(m.recall(KEY)).toBeNull();
    expect(m.size()).toBe(0);
  });

  test("evicts the oldest beyond MAX_ENTRIES", () => {
    const t = 1000;
    const m = new ApprovalMemory(60_000, () => t);
    for (let i = 0; i <= MAX_ENTRIES; i++) {
      m.remember({ ...KEY, target: `/t/${i}` }, "approved");
    }
    expect(m.size()).toBe(MAX_ENTRIES);
    expect(m.recall({ ...KEY, target: "/t/0" })).toBeNull(); // oldest evicted
    expect(m.recall({ ...KEY, target: `/t/${MAX_ENTRIES}` })).toBe("approved");
  });

  test("ttl <= 0 never remembers (defensive)", () => {
    const m = new ApprovalMemory(0, () => 0);
    m.remember(KEY, "approved");
    expect(m.recall(KEY)).toBeNull();
    expect(m.size()).toBe(0);
  });
});

describe("approvals config: remember_seconds", () => {
  test("defaults to 0 (off)", () => {
    const parsed = approvalsSchema.parse({});
    expect(parsed.remember_seconds).toBe(0);
  });
  test("bounds: 0..3600 integers only", () => {
    expect(approvalsSchema.safeParse({ remember_seconds: 3600 }).success).toBe(true);
    expect(approvalsSchema.safeParse({ remember_seconds: 3601 }).success).toBe(false);
    expect(approvalsSchema.safeParse({ remember_seconds: -1 }).success).toBe(false);
    expect(approvalsSchema.safeParse({ remember_seconds: 1.5 }).success).toBe(false);
  });
});
