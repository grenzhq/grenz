import { test, expect, describe } from "bun:test";
import { buildFirewallFeed } from "../src/firewall/feed.ts";
import type { LogEntry } from "../src/log/request-log.ts";

let nextId = 100;
function row(over: Partial<LogEntry & { id: number }>): LogEntry & { id: number } {
  return {
    id: nextId++,
    ts: 1000,
    agentId: "claude-code",
    upstream: "github",
    tool: "github",
    action: "repo:read",
    method: "GET",
    target: "/repos/o/r",
    decision: "deny",
    reason: "tripwire",
    forwarded: false,
    status: null,
    count: 0,
    shadow: false,
    delegationId: null,
    ...over,
  };
}

describe("buildFirewallFeed", () => {
  test("classifies each row and attaches the defense descriptor", () => {
    const events = buildFirewallFeed([row({ reason: "flow_denied" })]);
    expect(events).toHaveLength(1);
    expect(events[0]!.defense.kind).toBe("trifecta");
    expect(events[0]!.reason).toBe("flow_denied");
  });

  test("coalesces a run of same-(agent, reason) rows into one event with a count", () => {
    // Newest-first, as the log returns: tripwire cause, then a flood of revokes.
    const rows = [
      row({ id: 147, reason: "token_revoked" }),
      row({ id: 146, reason: "token_revoked" }),
      row({ id: 145, reason: "token_revoked" }),
      row({ id: 100, reason: "tripwire" }),
    ];
    const events = buildFirewallFeed(rows);
    expect(events).toHaveLength(2);
    expect(events[0]!.reason).toBe("token_revoked");
    expect(events[0]!.occurrences).toBe(3);
    expect(events[0]!.id).toBe(147); // newest row's id survives as the key
    expect(events[1]!.reason).toBe("tripwire"); // the cause is NOT buried
    expect(events[1]!.occurrences).toBe(1);
  });

  test("a different agent breaks a coalescing run", () => {
    const rows = [
      row({ id: 3, agentId: "a", reason: "token_revoked" }),
      row({ id: 2, agentId: "b", reason: "token_revoked" }),
      row({ id: 1, agentId: "a", reason: "token_revoked" }),
    ];
    const events = buildFirewallFeed(rows);
    expect(events.map((e) => e.agentId)).toEqual(["a", "b", "a"]);
    expect(events.every((e) => e.occurrences === 1)).toBe(true);
  });

  test("carries forwarded/shadow through so the UI can phrase shadow observations", () => {
    const events = buildFirewallFeed([
      row({ reason: "flow_denied", forwarded: true, shadow: true }),
    ]);
    expect(events[0]!.forwarded).toBe(true);
    expect(events[0]!.shadow).toBe(true);
  });

  test("empty input yields no events", () => {
    expect(buildFirewallFeed([])).toEqual([]);
  });
});
