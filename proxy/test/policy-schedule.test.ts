import { test, expect, describe } from "bun:test";
import { compilePolicyObject, type CompiledSchedule } from "../src/policy/compile.ts";
import { withinSchedule } from "../src/policy/schedule.ts";

function schedule(over: {
  timezone?: string;
  windows?: Array<{ days: string[]; start: string; end: string }>;
  on_closed?: "deny" | "require_approval";
}): CompiledSchedule {
  const r = compilePolicyObject({
    agent: "a", on_behalf_of: "b", grants: [],
    schedule: {
      timezone: over.timezone ?? "UTC",
      windows: over.windows ?? [{ days: ["mon", "tue", "wed", "thu", "fri"], start: "09:00", end: "17:00" }],
      ...(over.on_closed ? { on_closed: over.on_closed } : {}),
    },
  });
  if (!r.ok) throw new Error(r.error);
  if (r.policy.schedule === null) throw new Error("schedule did not compile");
  return r.policy.schedule;
}

// Fixed epochs (UTC): 2024-07-16 is a Tuesday.
const TUE_12_00_UTC = Date.UTC(2024, 6, 16, 12, 0); // Tue 12:00
const TUE_08_59_UTC = Date.UTC(2024, 6, 16, 8, 59); // Tue 08:59
const TUE_09_00_UTC = Date.UTC(2024, 6, 16, 9, 0); // Tue 09:00 (start, inclusive)
const TUE_17_00_UTC = Date.UTC(2024, 6, 16, 17, 0); // Tue 17:00 (end, exclusive)
const SUN_12_00_UTC = Date.UTC(2024, 6, 14, 12, 0); // Sunday

describe("withinSchedule", () => {
  test("inside a weekday window is open", () => {
    expect(withinSchedule(schedule({}), TUE_12_00_UTC)).toBe(true);
  });
  test("before start is closed; start is inclusive; end is exclusive", () => {
    const s = schedule({});
    expect(withinSchedule(s, TUE_08_59_UTC)).toBe(false);
    expect(withinSchedule(s, TUE_09_00_UTC)).toBe(true);
    expect(withinSchedule(s, TUE_17_00_UTC)).toBe(false);
  });
  test("a day not in the window is closed", () => {
    expect(withinSchedule(schedule({}), SUN_12_00_UTC)).toBe(false);
  });
  test("multiple windows: any match opens", () => {
    const s = schedule({
      windows: [
        { days: ["mon"], start: "09:00", end: "10:00" },
        { days: ["tue"], start: "12:00", end: "13:00" },
      ],
    });
    expect(withinSchedule(s, TUE_12_00_UTC)).toBe(true);
  });
  test("timezone shifts the verdict for the same instant", () => {
    // Tue 12:00 UTC is Tue 08:00 in New York -> before a 09:00 window there.
    const ny = schedule({ timezone: "America/New_York" });
    expect(withinSchedule(ny, TUE_12_00_UTC)).toBe(false);
    // Same instant in Tokyo is Tue 21:00 -> also outside 09:00-17:00.
    const tokyo = schedule({ timezone: "Asia/Tokyo" });
    expect(withinSchedule(tokyo, TUE_12_00_UTC)).toBe(false);
    // ...but 04:00 UTC is 13:00 in Tokyo -> open there, closed in UTC.
    const TUE_04_UTC = Date.UTC(2024, 6, 16, 4, 0);
    expect(withinSchedule(tokyo, TUE_04_UTC)).toBe(true);
    expect(withinSchedule(schedule({}), TUE_04_UTC)).toBe(false);
  });
});
