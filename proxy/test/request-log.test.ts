import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";

let dir: string;
let dbPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-log-"));
  dbPath = join(dir, "requests.db");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function entry(over: Partial<LogEntry>): LogEntry {
  return {
    ts: 1000,
    agentId: "claude-code",
    upstream: "github",
    tool: "github",
    action: "repo:read",
    method: "GET",
    target: "/repos/o/r",
    decision: "allow",
    reason: "explicit_allow",
    forwarded: true,
    status: 200,
    count: 1,
    ...over,
  };
}

describe("RequestLog", () => {
  test("records and reads back recent entries newest-first", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 1, action: "repo:read" }));
    log.record(entry({ ts: 2, action: "pr:create" }));
    const recent = log.recent(10);
    expect(recent.length).toBe(2);
    expect(recent[0]!.action).toBe("pr:create");
    expect(recent[1]!.action).toBe("repo:read");
    log.close();
  });

  test("recentByReasons filters to the given reasons, newest-first, with a stable id", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 1, decision: "allow", reason: "explicit_allow" }));
    log.record(entry({ ts: 2, decision: "deny", reason: "tripwire", forwarded: false, status: null, count: 0 }));
    log.record(entry({ ts: 3, decision: "allow", reason: "explicit_allow" }));
    log.record(entry({ ts: 4, decision: "deny", reason: "flow_denied", forwarded: false, status: null, count: 0 }));
    const events = log.recentByReasons(["tripwire", "flow_denied"], 10);
    expect(events.map((e) => e.reason)).toEqual(["flow_denied", "tripwire"]); // newest-first
    // ids are the SQLite rowids: monotonic, unique, newest has the larger id.
    expect(events[0]!.id).toBeGreaterThan(events[1]!.id);
    log.close();
  });

  test("recentByReasons honors the limit and returns [] for no reasons", () => {
    const log = new RequestLog(dbPath);
    for (let i = 0; i < 5; i++) {
      log.record(entry({ ts: i, decision: "deny", reason: "tripwire", forwarded: false, status: null, count: 0 }));
    }
    expect(log.recentByReasons(["tripwire"], 3).length).toBe(3);
    expect(log.recentByReasons([], 10)).toEqual([]);
    log.close();
  });

  test("countAllowedSince counts only allow decisions in window", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 100, decision: "allow" }));
    log.record(entry({ ts: 200, decision: "allow" }));
    log.record(entry({ ts: 250, decision: "deny", reason: "explicit_deny", forwarded: false, status: null, count: 0 }));
    log.record(entry({ ts: 50, decision: "allow" })); // before window
    expect(log.countAllowedSince("claude-code", 100)).toBe(2);
    expect(log.countAllowedSince("other-agent", 0)).toBe(0);
    log.close();
  });

  test("countAllowedSince sums the action count (MCP batches bill per action)", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 100, decision: "allow", count: 5 })); // one batch of 5 actions
    log.record(entry({ ts: 110, decision: "allow", count: 1 }));
    log.record(entry({ ts: 120, decision: "allow", reason: "upstream_error", forwarded: false, status: null, count: 0 }));
    expect(log.countAllowedSince("claude-code", 0)).toBe(6);
    log.close();
  });

  test("summary counts remembered approvals separately", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 100, decision: "allow", reason: "approval_granted" }));
    log.record(entry({ ts: 110, decision: "allow", reason: "approval_remembered_grant" }));
    log.record(entry({ ts: 120, decision: "allow", reason: "approval_remembered_grant" }));
    log.record(entry({ ts: 130, decision: "deny", reason: "approval_remembered_deny", forwarded: false, status: null, count: 0 }));
    const s = log.summary(0);
    expect(s.approvalGranted).toBe(1); // remembered rows are NOT lumped in
    expect(s.rememberedGrant).toBe(2);
    expect(s.rememberedDeny).toBe(1);
    expect(s.allow).toBe(3);
    expect(s.deny).toBe(1);
    log.close();
  });

  test("countAllowedSinceForUpstream scopes to one upstream, sums count, allow-only", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 100, decision: "allow", upstream: "github", count: 2 }));
    log.record(entry({ ts: 110, decision: "allow", upstream: "github", count: 1 }));
    log.record(entry({ ts: 120, decision: "allow", upstream: "slack", count: 5 }));
    log.record(entry({ ts: 130, decision: "deny", upstream: "github", reason: "explicit_deny", forwarded: false, status: null, count: 0 }));
    log.record(entry({ ts: 50, decision: "allow", upstream: "github", count: 9 })); // before window
    expect(log.countAllowedSinceForUpstream("claude-code", "github", 100)).toBe(3);
    expect(log.countAllowedSinceForUpstream("claude-code", "slack", 100)).toBe(5);
    expect(log.countAllowedSinceForUpstream("claude-code", "linear", 100)).toBe(0);
    expect(log.countAllowedSinceForUpstream("other-agent", "github", 0)).toBe(0);
    log.close();
  });

  test("agentActivity aggregates per agent (risk input)", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ decision: "allow", action: "repo:read" }));
    log.record(entry({ decision: "deny", action: "pr:merge", reason: "explicit_deny", forwarded: false, status: null, count: 0 }));
    log.record(entry({ decision: "deny", action: "repo:delete", reason: "explicit_deny", forwarded: false, status: null, count: 0 }));
    log.record(entry({ decision: "deny", action: "pr:merge", reason: "explicit_deny", forwarded: false, status: null, count: 0 }));
    const a = log.agentActivity("claude-code", 0);
    expect(a.total).toBe(4);
    expect(a.allow).toBe(1);
    expect(a.deny).toBe(3);
    expect(a.distinctDenied).toBe(2); // pr:merge + repo:delete (pr:merge counted once)
    expect(log.agentActivity("other", 0).total).toBe(0);
    log.close();
  });

  test("agentActivity counts rows, not cost — budget weights can't perturb risk", () => {
    const log = new RequestLog(dbPath);
    // A weighted forward stores its summed COST in `count` (here 25). Risk input
    // is row/decision based (COUNT(*)), so this contributes 1 allow, not 25 —
    // pinning that `budget.weights` never leaks into risk scoring.
    log.record(entry({ decision: "allow", action: "repo:delete", count: 25 }));
    const a = log.agentActivity("claude-code", 0);
    expect(a.allow).toBe(1);
    expect(a.total).toBe(1);
    log.close();
  });

  test("schema has no column that could hold a credential", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({}));
    log.close();
    // The row shape returned to callers contains only operational fields.
    const reopened = new RequestLog(dbPath);
    const row = reopened.recent(1)[0]!;
    const keys = Object.keys(row).sort();
    expect(keys).toEqual(
      ["action", "agentId", "count", "decision", "delegationId", "forwarded", "method", "reason", "shadow", "status", "target", "tool", "ts", "upstream"].sort(),
    );
    reopened.close();
  });

  test("recent() round-trips the shadow flag", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 1, action: "repo:read" })); // shadow defaults to falsey
    log.record(
      entry({ ts: 2, action: "pr:merge", decision: "deny", reason: "explicit_deny", shadow: true }),
    );
    const recent = log.recent(10);
    expect(recent[0]!.action).toBe("pr:merge");
    expect(recent[0]!.shadow).toBe(true);
    expect(recent[1]!.shadow).toBe(false);
    log.close();
  });

  test("recent() round-trips delegationId; rows without one stay null", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 1 })); // first-class agent: no delegation
    log.record(entry({ ts: 2, delegationId: "del_abc" }));
    const recent = log.recent(10);
    expect(recent[0]!.delegationId).toBe("del_abc");
    expect(recent[1]!.delegationId).toBe(null);
    log.close();
  });

  test("countAllowedSinceForDelegation scopes by delegation id, sums count, allow-only, windowed", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 100, delegationId: "del_a", count: 2 }));
    log.record(entry({ ts: 110, delegationId: "del_a", count: 1 }));
    log.record(entry({ ts: 120, delegationId: "del_b", count: 5 })); // sibling: separate pool
    log.record(entry({ ts: 130, delegationId: "del_a", decision: "deny", reason: "explicit_deny", forwarded: false, status: null, count: 0 }));
    log.record(entry({ ts: 50, delegationId: "del_a", count: 9 })); // before window
    log.record(entry({ ts: 140 })); // parent row (no delegation) — never counted here
    expect(log.countAllowedSinceForDelegation("del_a", 100)).toBe(3);
    expect(log.countAllowedSinceForDelegation("del_b", 100)).toBe(5);
    expect(log.countAllowedSinceForDelegation("del_zzz", 0)).toBe(0);
    log.close();
  });

  test("shadowWouldBlock groups shadow rows by (tool, action, decision), excluding non-shadow", () => {
    const log = new RequestLog(dbPath);
    // Two shadow would-denies of the same pair, one shadow would-approval, one ENFORCED deny.
    log.record(entry({ ts: 10, tool: "github", action: "pr:merge", decision: "deny", reason: "explicit_deny", shadow: true }));
    log.record(entry({ ts: 20, tool: "github", action: "pr:merge", decision: "deny", reason: "explicit_deny", shadow: true }));
    log.record(entry({ ts: 30, tool: "github", action: "issue:update", decision: "require_approval", reason: "approval_required", shadow: true }));
    log.record(entry({ ts: 40, tool: "github", action: "repo:delete", decision: "deny", reason: "explicit_deny", shadow: false }));
    log.record(entry({ ts: 5, tool: "github", action: "pr:merge", decision: "deny", reason: "explicit_deny", shadow: true })); // before window

    const rows = log.shadowWouldBlock(10);
    expect(rows).toEqual([
      { tool: "github", action: "issue:update", decision: "require_approval", n: 1 },
      { tool: "github", action: "pr:merge", decision: "deny", n: 2 },
    ]);
    log.close();
  });
});

describe("hasForwardedActionSince", () => {
  test("true only for a matching prior FORWARDED row within the window", () => {
    const log = new RequestLog(dbPath);
    log.record(entry({ ts: 5000, action: "pr:merge", forwarded: true }));
    expect(log.hasForwardedActionSince("claude-code", "github", "pr:merge", 0)).toBe(true);
    // Never-recorded action.
    expect(log.hasForwardedActionSince("claude-code", "github", "repo:delete", 0)).toBe(false);
    // Different agent / tool.
    expect(log.hasForwardedActionSince("other", "github", "pr:merge", 0)).toBe(false);
    expect(log.hasForwardedActionSince("claude-code", "linear", "pr:merge", 0)).toBe(false);
    // Before the window.
    expect(log.hasForwardedActionSince("claude-code", "github", "pr:merge", 6000)).toBe(false);
    log.close();
  });

  test("an allowed-but-not-forwarded row (upstream_error) is not a precedent", () => {
    const log = new RequestLog(dbPath);
    // decision=allow but forwarded=false — the action never reached upstream.
    log.record(entry({
      ts: 5000, action: "repo:delete", decision: "allow",
      reason: "upstream_error", forwarded: false, status: null, count: 0,
    }));
    expect(log.hasForwardedActionSince("claude-code", "github", "repo:delete", 0)).toBe(false);
    log.close();
  });
});
