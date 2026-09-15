import { test, expect } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { runPolicy } from "../src/cli/policy.ts";
import type { ParsedArgs } from "../src/cli/args.ts";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";
import { parseEvidenceDoc, buildEvidenceDoc, serializeEvidenceDoc } from "../src/policy/decay-evidence.ts";
import { parse as parseYaml } from "yaml";

const DAY = 86_400_000;

function seedHome(): string {
  const home = mkdtempSync(join(tmpdir(), "grenz-decaycli-"));
  writeFileSync(
    join(home, "grenz.yaml"),
    [
      "agents:",
      "  - id: swarm-1",
      `    token_hash: "${"0".repeat(64)}"`,
      "upstreams:",
      "  github:",
      "    type: github",
      "    base_url: https://api.github.com",
      "    credential: gh_token",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(home, "policy.yaml"),
    "agent: swarm-1\non_behalf_of: alice\ngrants:\n  - tool: github\n    allow:\n      - pr:read\n      - pr:merge\n",
  );
  return home;
}

function args(positionals: string[], flags: Record<string, string | boolean> = {}): ParsedArgs {
  return { positionals, flags: new Map(Object.entries(flags)) };
}

function entry(over: Partial<LogEntry>): LogEntry {
  return {
    ts: 0,
    agentId: "swarm-1",
    upstream: "github",
    tool: "github",
    action: "pr:read",
    method: "GET",
    target: "/x",
    decision: "allow",
    reason: "explicit_allow",
    forwarded: true,
    status: 200,
    count: 1,
    ...over,
  };
}

async function capture(fn: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const ow = process.stdout.write;
  const ew = process.stderr.write;
  process.stdout.write = ((s: string | Uint8Array) => (out.push(String(s)), true)) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => (err.push(String(s)), true)) as typeof process.stderr.write;
  try {
    const code = await fn();
    return { code, out: out.join(""), err: err.join("") };
  } finally {
    process.stdout.write = ow;
    process.stderr.write = ew;
  }
}

function seedStale(home: string): void {
  const now = Date.now();
  const log = new RequestLog(join(home, "requests.db"));
  log.record(entry({ ts: now - 90 * DAY, action: "pr:read" })); // coverage start (old)
  log.record(entry({ ts: now - 1 * DAY, action: "pr:read" })); // active
  log.record(entry({ ts: now - 60 * DAY, action: "pr:merge" })); // stale
  log.close();
}

test("decay prints candidate YAML to stdout, report to stderr", async () => {
  const home = seedHome();
  seedStale(home);
  const { code, out, err } = await capture(() => runPolicy(args(["decay"], { home })));
  expect(code).toBe(0);
  expect(out).toContain("agent: swarm-1"); // YAML on stdout
  expect(out).toContain("require_approval");
  expect(err).toContain("STALE");
  expect(err).toContain("✓ verified");
});

test("decay --out writes the candidate to a file", async () => {
  const home = seedHome();
  seedStale(home);
  const outPath = join(home, "candidate.yaml");
  const { code } = await capture(() => runPolicy(args(["decay"], { home, out: outPath })));
  expect(code).toBe(0);
  const yaml = readFileSync(outPath, "utf8");
  expect(yaml).toContain("pr:read");
  expect(yaml).toContain("pr:merge");
  expect(yaml).toContain("require_approval");
});

test("--report-only prints the report but no YAML", async () => {
  const home = seedHome();
  seedStale(home);
  const { code, out, err } = await capture(() => runPolicy(args(["decay"], { home, "report-only": true })));
  expect(code).toBe(0);
  expect(out).toBe("");
  expect(err).toContain("decay — agent swarm-1");
});

test("decay refuses --out onto the live policy.yaml (and leaves it untouched)", async () => {
  const home = seedHome();
  seedStale(home);
  const before = readFileSync(join(home, "policy.yaml"), "utf8");
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home, out: join(home, "policy.yaml") })));
  expect(code).toBe(1);
  expect(err).toContain("refusing to write");
  expect(readFileSync(join(home, "policy.yaml"), "utf8")).toBe(before);
});

test("decay refuses when the agent has no usage", async () => {
  const home = seedHome();
  new RequestLog(join(home, "requests.db")).close(); // empty db exists
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home })));
  expect(code).toBe(1);
  expect(err).toContain("no usage recorded");
});

test("a typo'd --agent names the typed id in the refusal, not the policy default", async () => {
  const home = seedHome();
  seedStale(home); // usage exists for swarm-1, but NOT for the typo'd id
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home, agent: "swrm-1-typo" })));
  expect(code).toBe(1);
  expect(err).toContain("no usage recorded for agent swrm-1-typo");
  expect(err).not.toContain("swarm-1 —"); // did NOT name the policy default
});

test("fleet mode (policy_source configured) prints a peer-usage warning", async () => {
  const home = seedHome();
  // Add a policy_source block so the config is in fleet mode.
  writeFileSync(
    join(home, "grenz.yaml"),
    [
      "agents:",
      "  - id: swarm-1",
      `    token_hash: "${"0".repeat(64)}"`,
      "upstreams:",
      "  github:",
      "    type: github",
      "    base_url: https://api.github.com",
      "    credential: gh_token",
      "policy_source:",
      "  url: https://plane.example.com/policy",
      "",
    ].join("\n"),
  );
  seedStale(home);
  const demote = await capture(() => runPolicy(args(["decay"], { home })));
  expect(demote.code).toBe(0);
  expect(demote.err).toContain("fleet mode");
  const drop = await capture(() => runPolicy(args(["decay"], { home, drop: true })));
  expect(drop.code).toBe(0);
  expect(drop.err).toContain("FLEET + --drop");
});

test("decay errors when there is no request log at all", async () => {
  const home = seedHome();
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home })));
  expect(code).toBe(1);
  expect(err).toContain("no request log yet");
});

test("decay export writes this proxy's per-agent usage as an evidence doc", async () => {
  const home = seedHome();
  seedStale(home); // pr:read active, pr:merge stale (permitted+forwarded rows)
  const { code, out } = await capture(() => runPolicy(args(["decay", "export"], { home, proxy: "us-east-1a" })));
  expect(code).toBe(0);
  const parsed = parseEvidenceDoc(out);
  expect(parsed.ok).toBe(true);
  if (parsed.ok) {
    expect(parsed.doc.agent).toBe("swarm-1");
    expect(parsed.doc.proxy).toBe("us-east-1a");
    const actions = parsed.doc.actions.map((a) => a.action).sort();
    expect(actions).toContain("pr:read");
    expect(actions).toContain("pr:merge");
  }
});

test("decay export --out writes to a file", async () => {
  const home = seedHome();
  seedStale(home);
  const outPath = join(home, "evidence.json");
  const { code } = await capture(() => runPolicy(args(["decay", "export"], { home, out: outPath })));
  expect(code).toBe(0);
  expect(parseEvidenceDoc(readFileSync(outPath, "utf8")).ok).toBe(true);
});

function writeEvidence(
  home: string,
  name: string,
  agent: string,
  action: string,
  lastTs: number,
  generatedAt: number = Date.now(),
): string {
  const p = join(home, name);
  writeFileSync(
    p,
    serializeEvidenceDoc(buildEvidenceDoc(agent, "peer-b", generatedAt, [{ tool: "github", action, lastTs, n: 5 }])),
  );
  return p;
}

/** Parse decay's stdout YAML and return the github grant's allow/require_approval. */
function ghGrant(out: string): { allow: string[]; require_approval: string[] } {
  const g = parseYaml(out).grants[0];
  return { allow: g.allow ?? [], require_approval: g.require_approval ?? [] };
}

test("fleet evidence vetoes a demotion: a locally-stale action fresh on a peer is KEPT", async () => {
  const home = seedHome();
  seedStale(home); // pr:merge stale locally (now-60d), pr:read active, coverage now-90d
  const ev = writeEvidence(home, "peer.json", "swarm-1", "pr:merge", Date.now() - 1 * DAY); // fresh on peer
  const { code, out, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  const g = ghGrant(out);
  expect(g.allow).toContain("pr:merge"); // kept in allow
  expect(g.require_approval).not.toContain("pr:merge"); // NOT demoted
  expect(err).toContain("fleet evidence");
});

test("a different-agent evidence file is skipped (no cross-agent veto)", async () => {
  const home = seedHome();
  seedStale(home);
  const ev = writeEvidence(home, "other.json", "swarm-2", "pr:merge", Date.now() - 1 * DAY);
  const { code, out, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  expect(err).toContain("skipping"); // warned
  expect(ghGrant(out).require_approval).toContain("pr:merge"); // pr:merge STILL demoted
});

test("an older fleet lastTs does not change the classification", async () => {
  const home = seedHome();
  seedStale(home);
  const ev = writeEvidence(home, "old.json", "swarm-1", "pr:merge", Date.now() - 70 * DAY); // still stale
  const { code, out } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  expect(ghGrant(out).require_approval).toContain("pr:merge"); // still demoted
});

test("a malformed evidence file fails closed", async () => {
  const home = seedHome();
  seedStale(home);
  const bad = join(home, "bad.json");
  writeFileSync(bad, "{not json");
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: bad })));
  expect(code).toBe(1);
  expect(err).toContain("invalid evidence");
});

test("an out-of-range lastTs fails closed at the schema (never crashes the report)", async () => {
  const home = seedHome();
  seedStale(home);
  const bad = join(home, "overflow.json");
  // 9e15 > max representable Date ms (8.64e15) — must be rejected, not throw in fmtDate.
  writeFileSync(bad, JSON.stringify({ agent: "swarm-1", generatedAt: 0, actions: [{ tool: "github", action: "pr:merge", lastTs: 9_000_000_000_000_000, n: 5 }] }));
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: bad })));
  expect(code).toBe(1);
  expect(err).toContain("invalid evidence");
});

test("fleet evidence never extends coverage: a young local log still decays nothing", async () => {
  const home = seedHome();
  // Young local log: only 3 days of coverage (< 30d threshold).
  const now = Date.now();
  const log = new RequestLog(join(home, "requests.db"));
  log.record(entry({ ts: now - 3 * DAY, action: "pr:read" }));
  log.close();
  // Rich, fresh fleet evidence for BOTH grants.
  const ev = join(home, "rich.json");
  writeFileSync(
    ev,
    serializeEvidenceDoc(
      buildEvidenceDoc("swarm-1", "peer-b", now, [
        { tool: "github", action: "pr:read", lastTs: now - 1 * DAY, n: 9 },
        { tool: "github", action: "pr:merge", lastTs: now - 1 * DAY, n: 9 },
      ]),
    ),
  );
  const { code, out, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  // Coverage is LOCAL and young → nothing decays, and the header must NOT over-claim a veto.
  expect(ghGrant(out).require_approval).toEqual([]);
  expect(err).toContain("INSUFFICIENT");
  expect(err).toContain("0 action(s) kept");
});

test("a fleet action unreachable by any allow pattern is inert", async () => {
  const home = seedHome();
  seedStale(home);
  // "billing:invoice" is not in the github vocabulary and not reachable by pr:read/pr:merge.
  const ev = writeEvidence(home, "inert.json", "swarm-1", "billing:invoice", Date.now() - 1 * DAY);
  const { code, out, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  expect(err).toContain("0 action(s) kept"); // no veto — the action isn't a decay candidate
  expect(ghGrant(out).require_approval).toContain("pr:merge"); // pr:merge still demoted
});

test("veto near the boundary: a peer lastTs just inside the window keeps", async () => {
  const home = seedHome();
  seedStale(home);
  // pr:merge locally stale; peer lastTs 29d ago — inside the 30d window → ACTIVE.
  // (The exact lastTs == staleBefore identity is pinned deterministically at the
  // planner level in decay.test.ts, where `now` is controlled; the CLI computes
  // its own now, so this uses an unambiguously-fresh ts to avoid clock skew.)
  const ev = writeEvidence(home, "boundary.json", "swarm-1", "pr:merge", Date.now() - 29 * DAY);
  const { code, out } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  expect(ghGrant(out).allow).toContain("pr:merge"); // kept
});

test("a stale export (older than the window) warns the operator", async () => {
  const home = seedHome();
  seedStale(home);
  // Fresh lastTs but the SNAPSHOT was taken 60d ago (generatedAt old).
  const ev = writeEvidence(home, "old-snap.json", "swarm-1", "pr:merge", Date.now() - 1 * DAY, Date.now() - 60 * DAY);
  const { code, err } = await capture(() => runPolicy(args(["decay"], { home, evidence: ev })));
  expect(code).toBe(0);
  expect(err).toContain("exported 60d ago");
});
