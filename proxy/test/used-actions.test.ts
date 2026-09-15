import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";

function row(over: Partial<LogEntry>): LogEntry {
  return {
    ts: 1000,
    agentId: "claude-code",
    upstream: "github",
    tool: "github",
    action: "repo:read",
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

describe("RequestLog.usedActions", () => {
  let dir: string;
  let log: RequestLog;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "grenz-used-"));
    log = new RequestLog(join(dir, "r.db"));
  });
  afterEach(async () => {
    log.close();
    await rm(dir, { recursive: true, force: true });
  });

  test("returns only explicit_allow rows, distinct, agent-scoped, windowed", () => {
    log.record(row({ action: "repo:read", ts: 2000 }));
    log.record(row({ action: "repo:read", ts: 2500 })); // dup -> collapses
    log.record(row({ action: "issue:create", ts: 2600 }));
    log.record(row({ action: "pr:merge", decision: "deny", reason: "explicit_deny", ts: 2700 })); // denied
    log.record(row({ action: "issue:update", reason: "approval_granted", ts: 2800 })); // approval
    log.record(row({ action: "repo:read", agentId: "other", ts: 2900 })); // other agent
    log.record(row({ action: "old:action", ts: 500 })); // before window
    const used = log.usedActions("claude-code", 1000);
    expect(used).toEqual([
      { tool: "github", action: "issue:create" },
      { tool: "github", action: "repo:read" },
    ]);
  });
});
