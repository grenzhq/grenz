/**
 * Pure schedule-window comparator. Given a compiled schedule and an instant,
 * decide whether that instant falls inside any open window — rendering the
 * instant in the schedule's IANA timezone. Deterministic given its inputs:
 * no ambient clock, no network. The proxy passes the injectable timestamp.
 */
import type { CompiledSchedule, Weekday } from "./compile.ts";

const WEEKDAY_BY_LABEL: Record<string, Weekday> = {
  Mon: "mon", Tue: "tue", Wed: "wed", Thu: "thu", Fri: "fri", Sat: "sat", Sun: "sun",
};

export function withinSchedule(schedule: CompiledSchedule, epochMs: number): boolean {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: schedule.timezone,
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(new Date(epochMs));

  let weekday: Weekday | null = null;
  let hour = 0;
  let minute = 0;
  for (const p of parts) {
    if (p.type === "weekday") weekday = WEEKDAY_BY_LABEL[p.value] ?? null;
    else if (p.type === "hour") hour = Number(p.value) % 24; // "24:00" midnight edge -> 0
    else if (p.type === "minute") minute = Number(p.value);
  }
  if (weekday === null) return false;

  const mins = hour * 60 + minute;
  const wd = weekday;
  return schedule.windows.some((w) => w.days.has(wd) && mins >= w.startMin && mins < w.endMin);
}
