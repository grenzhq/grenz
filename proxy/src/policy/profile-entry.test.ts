import { test, expect } from "bun:test";
import { profileEntrySchema, PROFILE_NAME_RE, MAX_PROFILE_POLICY_BYTES } from "./profile-entry.ts";

test("accepts a valid entry", () => {
  expect(profileEntrySchema.safeParse({ name: "ci", policy: "grants: []\n" }).success).toBe(true);
});
test("rejects a bad name", () => {
  expect(profileEntrySchema.safeParse({ name: "CI bad", policy: "x" }).success).toBe(false);
  expect(profileEntrySchema.safeParse({ name: "-lead", policy: "x" }).success).toBe(false);
});
test("rejects unknown keys (strict)", () => {
  expect(profileEntrySchema.safeParse({ name: "ci", policy: "x", extra: 1 }).success).toBe(false);
});
test("rejects an over-long policy", () => {
  expect(profileEntrySchema.safeParse({ name: "ci", policy: "a".repeat(MAX_PROFILE_POLICY_BYTES + 1) }).success).toBe(false);
});
test("PROFILE_NAME_RE matches the Slice-2 shape", () => {
  expect(PROFILE_NAME_RE.test("ci")).toBe(true);
  expect(PROFILE_NAME_RE.test("build-2")).toBe(true);
  expect(PROFILE_NAME_RE.test("Bad")).toBe(false);
});
