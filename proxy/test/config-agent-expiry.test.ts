import { test, expect, describe } from "bun:test";
import { agentSchema } from "../src/config/schema.ts";

const base = { id: "a", token_hash: "a".repeat(64) };

describe("agent expires_at", () => {
  test("absent → expiresAtMs null", () => {
    expect(agentSchema.parse(base)).toMatchObject({ expiresAtMs: null });
  });
  test("valid RFC3339 (Z) → epoch ms", () => {
    const p = agentSchema.parse({ ...base, expires_at: "2026-08-01T00:00:00Z" });
    expect(p.expiresAtMs).toBe(Date.parse("2026-08-01T00:00:00Z"));
  });
  test("offset form parses", () => {
    expect(agentSchema.parse({ ...base, expires_at: "2026-08-01T02:00:00+02:00" }).expiresAtMs).toBe(
      Date.parse("2026-08-01T02:00:00+02:00"),
    );
  });
  test("zone-less local datetime is rejected", () => {
    expect(() => agentSchema.parse({ ...base, expires_at: "2026-08-01T00:00:00" })).toThrow();
  });
  test("garbage is rejected at load (not silently 'never expires')", () => {
    expect(() => agentSchema.parse({ ...base, expires_at: "nope" })).toThrow();
  });
  test("a decoy that expires is rejected", () => {
    expect(() => agentSchema.parse({ ...base, decoy: true, expires_at: "2026-08-01T00:00:00Z" })).toThrow(/decoy/i);
  });
  test("a decoy without expiry still parses", () => {
    expect(agentSchema.parse({ ...base, decoy: true })).toMatchObject({ decoy: true, expiresAtMs: null });
  });
});
