import { test, expect } from "bun:test";
import { mergeProfilesOverDefault } from "./merge.ts";
import { compilePolicyYaml, type CompiledPolicy } from "./compile.ts";

function compile(y: string): CompiledPolicy { const r = compilePolicyYaml(y); if (!r.ok) throw new Error(r.error); return r.policy; }
const DEF = "agent: root\non_behalf_of: user\ngrants:\n  - tool: github\n    allow: [\"pr:read\"]\ntripwires:\n  - action: \"danger:*\"\n";
const CI = "agent: a\non_behalf_of: u\ngrants:\n  - tool: github\n    allow: [\"pr:merge\"]\n";
const declared = (...n: string[]) => new Set(n);

test("merges grants over the default, keyed by name", () => {
  const r = mergeProfilesOverDefault(compile(DEF), [{ name: "ci", policy: CI }], declared("ci"));
  expect(r.ok).toBe(true);
  if (r.ok) expect([...r.profiles.get("ci")!.grants.keys()]).toContain("github");
});
test("grants-only: a profile inherits the default's protections (tripwires)", () => {
  const d = compile(DEF);
  const r = mergeProfilesOverDefault(d, [{ name: "ci", policy: CI }], declared("ci"));
  expect(r.ok).toBe(true);
  if (r.ok) expect(r.profiles.get("ci")!.tripwires).toBe(d.tripwires);
});
test("rejects an undeclared name → code undeclared, no partial map", () => {
  const r = mergeProfilesOverDefault(compile(DEF), [{ name: "nope", policy: CI }], declared("ci"));
  expect(r.ok).toBe(false);
  if (!r.ok) { expect(r.code).toBe("undeclared"); expect(r.name).toBe("nope"); }
});
test("rejects a duplicate name → code duplicate (both entries compile, so the guard is what fires)", () => {
  const r = mergeProfilesOverDefault(compile(DEF), [{ name: "ci", policy: CI }, { name: "ci", policy: CI }], declared("ci"));
  expect(r.ok).toBe(false);
  if (!r.ok) { expect(r.code).toBe("duplicate"); expect(r.error).toContain("duplicate"); }
});
test("rejects a non-compiling profile → code parse_error, error carries detail", () => {
  const r = mergeProfilesOverDefault(compile(DEF), [{ name: "ci", policy: "this: is: not: valid: [" }], declared("ci"));
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.code).toBe("parse_error");
});
