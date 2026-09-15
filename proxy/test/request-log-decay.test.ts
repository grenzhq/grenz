import { test, expect } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync } from "node:fs";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";

function tmpDb(): string {
  return join(mkdtempSync(join(tmpdir(), "grenz-decaylog-")), "log.db");
}

function entry(over: Partial<LogEntry>): LogEntry {
  return {
    ts: 1_000,
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

test("coverageStart is null on an empty log", () => {
  const log = new RequestLog(tmpDb());
  expect(log.coverageStart()).toBeNull();
  log.close();
});

test("coverageStart is the global MIN(ts) across all agents", () => {
  const log = new RequestLog(tmpDb());
  log.record(entry({ ts: 5_000, agentId: "swarm-1" }));
  log.record(entry({ ts: 2_000, agentId: "other" }));
  log.record(entry({ ts: 9_000, agentId: "swarm-1" }));
  expect(log.coverageStart()).toBe(2_000);
  log.close();
});

test("coverageStart(agentId) is the agent's own earliest row (renamed-agent safety)", () => {
  const log = new RequestLog(tmpDb());
  log.record(entry({ ts: 1_000, agentId: "old-id" })); // an older, DIFFERENT agent
  log.record(entry({ ts: 8_000, agentId: "swarm-1-eu" })); // the new agent's first row
  log.record(entry({ ts: 9_000, agentId: "swarm-1-eu" }));
  expect(log.coverageStart()).toBe(1_000); // global: whole log
  expect(log.coverageStart("swarm-1-eu")).toBe(8_000); // per-agent: only this agent's window
  expect(log.coverageStart("never-seen")).toBeNull();
  log.close();
});

test("lastUsedActions returns MAX(ts) and COUNT per (tool, action), explicit_allow only", () => {
  const log = new RequestLog(tmpDb());
  log.record(entry({ ts: 1_000, action: "pr:read" }));
  log.record(entry({ ts: 4_000, action: "pr:read" }));
  log.record(entry({ ts: 2_000, action: "pr:merge" }));
  // A denied row and an approval row must NOT count as usage evidence.
  log.record(
    entry({ ts: 9_000, action: "pr:close", decision: "deny", reason: "no_matching_allow", forwarded: false, status: null }),
  );
  log.record(
    entry({ ts: 9_000, action: "pr:merge", decision: "require_approval", reason: "approval_required", forwarded: false, status: null }),
  );
  const rows = log.lastUsedActions("swarm-1");
  expect(rows).toEqual([
    { tool: "github", action: "pr:merge", lastTs: 2_000, n: 1 },
    { tool: "github", action: "pr:read", lastTs: 4_000, n: 2 },
  ]);
  log.close();
});

test("lastUsedActions counts all permitted-and-forwarded exercise, not shadow/error/deny", () => {
  const log = new RequestLog(tmpDb());
  // Permitted + forwarded — all three reasons must count:
  log.record(entry({ ts: 1_000, action: "pr:read", reason: "explicit_allow", forwarded: true, shadow: false }));
  log.record(entry({ ts: 2_000, action: "pr:merge", reason: "approval_granted", forwarded: true, shadow: false }));
  log.record(entry({ ts: 3_000, action: "pr:close", reason: "jit_grant", forwarded: true, shadow: false }));
  // Must NOT count:
  log.record(entry({ ts: 9_000, action: "pr:evil", reason: "explicit_deny", forwarded: true, shadow: true })); // shadow observation
  log.record(entry({ ts: 9_000, action: "pr:oops", reason: "upstream_error", forwarded: false, status: null })); // never forwarded
  log.record(entry({ ts: 9_000, action: "pr:nope", reason: "no_matching_allow", forwarded: false, status: null })); // deny
  const got = log.lastUsedActions("swarm-1").map((r) => r.action);
  expect(got).toEqual(["pr:close", "pr:merge", "pr:read"]); // sorted, only the permitted+forwarded three
});

test("lastUsedActions is scoped to the agent", () => {
  const log = new RequestLog(tmpDb());
  log.record(entry({ agentId: "swarm-1", action: "pr:read", ts: 1_000 }));
  log.record(entry({ agentId: "other", action: "pr:merge", ts: 1_000 }));
  const rows = log.lastUsedActions("swarm-1");
  expect(rows.map((r) => r.action)).toEqual(["pr:read"]);
  log.close();
});
