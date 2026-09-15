import { test, expect } from "bun:test";
import { buildEvidenceDoc, serializeEvidenceDoc, parseEvidenceDoc } from "../src/policy/decay-evidence.ts";

test("build → serialize → parse round-trips", () => {
  const doc = buildEvidenceDoc("swarm-1", "us-east-1a", 1_752_800_000_000, [
    { tool: "github", action: "pr:merge", lastTs: 1_752_700_000_000, n: 47 },
    { tool: "github", action: "pr:read", lastTs: 1_752_790_000_000, n: 1204 },
  ]);
  const parsed = parseEvidenceDoc(serializeEvidenceDoc(doc));
  expect(parsed.ok).toBe(true);
  if (parsed.ok) expect(parsed.doc).toEqual(doc);
});

test("proxy label is omitted when not given", () => {
  const doc = buildEvidenceDoc("swarm-1", undefined, 1_000, []);
  expect("proxy" in doc).toBe(false);
  expect(doc.actions).toEqual([]);
});

test("parse rejects malformed JSON", () => {
  const r = parseEvidenceDoc("{not json");
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.error).toContain("JSON");
});

test("parse rejects an unknown key (strict) and a missing field", () => {
  expect(parseEvidenceDoc(JSON.stringify({ agent: "a", generatedAt: 1, actions: [], extra: 1 })).ok).toBe(false);
  expect(parseEvidenceDoc(JSON.stringify({ generatedAt: 1, actions: [] })).ok).toBe(false); // no agent
});

test("parse rejects a non-integer lastTs", () => {
  const bad = { agent: "a", generatedAt: 1, actions: [{ tool: "t", action: "x", lastTs: 1.5, n: 1 }] };
  expect(parseEvidenceDoc(JSON.stringify(bad)).ok).toBe(false);
});
