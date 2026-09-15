import { test, expect } from "bun:test";
import { adoptSignedStartup, startupProfileEntries } from "../src/cli/run-profiles.ts";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import type { ProfileEntry } from "../src/policy/profile-entry.ts";

function def(): CompiledPolicy {
  const r = compilePolicyYaml("agent: r\non_behalf_of: u\ngrants: []\n");
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}
const CI = "agent: a\non_behalf_of: u\ngrants: []\n";
const signedOk = (profiles: { name: string; policy: string }[] | null) => ({
  ok: true as const,
  policy: def(),
  policyYaml: "y",
  version: 7,
  digest: "d",
  unchanged: false,
  profiles,
});

test("F1: a bad bundle profile → !ok AND accept was NEVER called", () => {
  let accepted = false;
  const r = adoptSignedStartup({
    signed: signedOk([{ name: "ci", policy: "not: : yaml: [" }]),
    declaredNames: new Set(["ci"]),
    accept: () => {
      accepted = true;
    },
    now: () => 1,
  });
  expect(r.ok).toBe(false);
  expect(accepted).toBe(false); // the floor is NOT burned for a refused bundle
});

test("F6: an undeclared bundle profile → !ok, accept never called", () => {
  let accepted = false;
  const r = adoptSignedStartup({
    signed: signedOk([{ name: "nope", policy: CI }]),
    declaredNames: new Set(["ci"]),
    accept: () => {
      accepted = true;
    },
    now: () => 1,
  });
  expect(r.ok).toBe(false);
  expect(accepted).toBe(false);
});

test("F3: absent profiles → entries [], accept called (clear is valid)", () => {
  let acceptedV = 0;
  const r = adoptSignedStartup({
    signed: signedOk(null),
    declaredNames: new Set(["ci"]),
    accept: (v) => {
      acceptedV = v;
    },
    now: () => 1,
  });
  expect(r.ok && r.entries).toEqual([]);
  expect(acceptedV).toBe(7);
});

test("good v2 profiles → entries pass through, accept called with version", () => {
  let acceptedV = 0;
  const r = adoptSignedStartup({
    signed: signedOk([{ name: "ci", policy: CI }]),
    declaredNames: new Set(["ci"]),
    accept: (v) => {
      acceptedV = v;
    },
    now: () => 1,
  });
  expect(r.ok && r.entries.length).toBe(1);
  expect(acceptedV).toBe(7);
});

// startupProfileEntries — the F2 selection in one place: signed mode entries are
// bundle-only, never local; a failed signed pull yields [] even with local files.
const BUNDLE: readonly ProfileEntry[] = [{ name: "ci", policy: CI }];
const LOCAL: readonly ProfileEntry[] = [{ name: "ci", policy: CI }, { name: "triage", policy: CI }];

test("startupProfileEntries: signed + ok → the bundle entries", () => {
  expect(
    startupProfileEntries({ signedMode: true, signedPullOk: true, bundleEntries: BUNDLE, localEntries: LOCAL }),
  ).toBe(BUNDLE);
});

test("startupProfileEntries: signed + !ok → [] (F2 fail-open-prevention), NOT the local set", () => {
  const out = startupProfileEntries({
    signedMode: true,
    signedPullOk: false,
    bundleEntries: [],
    localEntries: LOCAL, // non-empty on purpose: a failed pull must still ignore it
  });
  expect(out).toEqual([]);
  expect(out).not.toBe(LOCAL);
});

test("startupProfileEntries: non-signed → the local set (both pull-ok values)", () => {
  expect(
    startupProfileEntries({ signedMode: false, signedPullOk: true, bundleEntries: BUNDLE, localEntries: LOCAL }),
  ).toBe(LOCAL);
  expect(
    startupProfileEntries({ signedMode: false, signedPullOk: false, bundleEntries: BUNDLE, localEntries: LOCAL }),
  ).toBe(LOCAL);
});
