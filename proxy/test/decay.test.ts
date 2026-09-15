import { test, expect } from "bun:test";
import {
  decayPolicy,
  evidenceKey,
  formatDecayReport,
  type DecayEvidence,
  type DecayMode,
  type FleetContext,
} from "../src/policy/decay.ts";
import type { PolicySource } from "../src/policy/schema.ts";

const GH_VOCAB = ["pr:read", "pr:create", "pr:merge", "pr:comment", "actions:dispatch"] as const;
const DAY = 86_400_000;
const NOW = 100 * DAY;

function vocab(map: Record<string, readonly string[] | null>): Map<string, readonly string[] | null> {
  return new Map(Object.entries(map));
}

function evidence(used: Record<string, number>, coverageStart: number | null): DecayEvidence {
  const lastUsed = new Map<string, { lastTs: number; n: number }>();
  let rows = 0;
  for (const [k, ts] of Object.entries(used)) {
    const i = k.indexOf(":");
    const tool = k.slice(0, i);
    const action = k.slice(i + 1);
    lastUsed.set(evidenceKey(tool, action), { lastTs: ts, n: 1 });
    rows += 1;
  }
  return { lastUsed, coverageStart, agentUsageRows: rows };
}

function policy(allow: PolicySource["grants"][number]["allow"]): PolicySource {
  return {
    agent: "swarm-1",
    on_behalf_of: "alice",
    grants: [{ tool: "github", allow, deny: [], require_approval: [] }],
    pins: [],
    responses: [],
  } as PolicySource;
}

const opts = (mode: DecayMode) => ({ now: NOW, staleDays: 30, mode, agentId: "swarm-1" });

test("zero-usage log → refusal (never a strip-everything proposal)", () => {
  const r = decayPolicy(policy(["pr:read"]), vocab({ github: GH_VOCAB }), evidence({}, null), opts("demote"));
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.reason).toContain("no usage recorded");
});

test("young log (coverage < threshold) → proposal identical to source", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY }, NOW - 3 * DAY);
  const r = decayPolicy(policy(["pr:read", "pr:merge"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual(["pr:read", "pr:merge"]);
    expect(r.report.covered).toBe(false);
  }
});

test("active action (lastTs == staleBefore boundary) is kept", () => {
  const staleBefore = NOW - 30 * DAY;
  const ev = evidence({ "github:pr:read": staleBefore }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual(["pr:read"]);
    expect(r.source.grants[0]!.require_approval).toEqual([]);
    expect(r.report.actions.find((a) => a.action === "pr:read")!.cls).toBe("active");
  }
});

test("coverageStart == staleBefore boundary counts as covered (no-row action → unused)", () => {
  const staleBefore = NOW - 30 * DAY;
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY }, staleBefore);
  const r = decayPolicy(policy(["pr:read", "actions:dispatch"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.report.actions.find((a) => a.action === "actions:dispatch")!.cls).toBe("unused");
  }
});

test("stale action demote → moved to require_approval as a literal", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read", "pr:merge"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual(["pr:read"]);
    expect(r.source.grants[0]!.require_approval).toEqual(["pr:merge"]);
  }
});

test("stale action drop → removed entirely, not demoted", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read", "pr:merge"]), vocab({ github: GH_VOCAB }), ev, opts("drop"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual(["pr:read"]);
    expect(r.source.grants[0]!.require_approval).toEqual([]);
  }
});

test("partial pattern split: pr:* → keep active literal, demote stale + unused", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:*"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    // pr:read active → kept; pr:merge stale, pr:create/pr:comment unused → demoted.
    expect(r.source.grants[0]!.allow).toEqual(["pr:read"]);
    expect([...r.source.grants[0]!.require_approval].sort()).toEqual(["pr:comment", "pr:create", "pr:merge"]);
  }
});

test("covered log: active kept, never-used action decayed", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read", "pr:create"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual(["pr:read"]);
    expect(r.source.grants[0]!.require_approval).toEqual(["pr:create"]);
  }
});

test("rule-object fidelity: split preserves targets and message", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const src = policy([{ action: "pr:*", targets: ["myorg/*"], message: "scoped" }]);
  const r = decayPolicy(src, vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual([{ action: "pr:read", targets: ["myorg/*"], message: "scoped" }]);
    expect(r.source.grants[0]!.require_approval).toContainEqual({ action: "pr:merge", targets: ["myorg/*"], message: "scoped" });
  }
});

test("demote dedupes against an existing equivalent require_approval rule", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const src: PolicySource = {
    agent: "swarm-1",
    on_behalf_of: "alice",
    grants: [{ tool: "github", allow: ["pr:read", "pr:merge"], deny: [], require_approval: ["pr:merge"] }],
    pins: [],
    responses: [],
  } as PolicySource;
  const r = decayPolicy(src, vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) expect(r.source.grants[0]!.require_approval).toEqual(["pr:merge"]); // no duplicate
});

test("dead pattern is kept verbatim and reported", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read", "bogus:typo"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toContain("bogus:typo");
    expect(r.report.changes.find((c) => c.pattern === "bogus:typo")!.disposition).toBe("dead");
  }
});

test("generic mcp grant is never rewritten (report only)", () => {
  const src: PolicySource = {
    agent: "swarm-1",
    on_behalf_of: "alice",
    grants: [{ tool: "billing", allow: ["invoice:*"], deny: [], require_approval: [] }],
    pins: [],
    responses: [],
  } as PolicySource;
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(src, vocab({ billing: null }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(r.source.grants[0]!.allow).toEqual(["invoice:*"]);
    expect(r.report.changes[0]!.disposition).toBe("mcp_skipped");
  }
});

test("formatDecayReport surfaces STALE + verify + insufficient-coverage lines", () => {
  const staleEv = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const stale = decayPolicy(policy(["pr:read", "pr:merge"]), vocab({ github: GH_VOCAB }), staleEv, opts("demote"));
  expect(stale.ok).toBe(true);
  if (stale.ok) {
    const out = formatDecayReport(stale.report, true);
    expect(out).toContain("STALE");
    expect(out).toContain("demote");
    expect(out).toContain("✓ verified");
  }
  const youngEv = evidence({ "github:pr:read": NOW - 1 * DAY }, NOW - 3 * DAY);
  const young = decayPolicy(policy(["pr:read"]), vocab({ github: GH_VOCAB }), youngEv, opts("demote"));
  expect(young.ok).toBe(true);
  if (young.ok) expect(formatDecayReport(young.report, true)).toContain("INSUFFICIENT");
});

test("formatDecayReport omits the verified line unless the caller asserts it", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 60 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read", "pr:merge"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    expect(formatDecayReport(r.report)).not.toContain("✓ verified"); // default: not asserted
    expect(formatDecayReport(r.report, true)).toContain("✓ verified");
  }
});

test("formatDecayReport annotates fleet-vetoed actions and prints the fleet header", () => {
  const ev = evidence({ "github:pr:read": NOW - 1 * DAY, "github:pr:merge": NOW - 1 * DAY }, NOW - 90 * DAY);
  const r = decayPolicy(policy(["pr:read", "pr:merge"]), vocab({ github: GH_VOCAB }), ev, opts("demote"));
  expect(r.ok).toBe(true);
  if (r.ok) {
    const fleet: FleetContext = { files: ["peer-b"], vetoedKeys: new Set([evidenceKey("github", "pr:merge")]) };
    const out = formatDecayReport(r.report, true, fleet);
    expect(out).toContain("fleet evidence: 1 file(s)");
    expect(out).toMatch(/pr:merge\s+ACTIVE.*\(fleet\)/);
  }
});

test("refusal message names the queried agent, not the policy default", () => {
  const r = decayPolicy(policy(["pr:read"]), vocab({ github: GH_VOCAB }), evidence({}, null), {
    now: NOW,
    staleDays: 30,
    mode: "demote",
    agentId: "typo-id",
  });
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.reason).toContain("typo-id");
});
