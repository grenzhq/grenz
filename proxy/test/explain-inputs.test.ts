import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compilePolicyYaml, type CompiledPolicy } from "../src/policy/compile.ts";
import { collectExplainInputs } from "../src/explain/inputs.ts";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";
import { RevocationStore } from "../src/revoke/store.ts";
import { GrantStore } from "../src/grant/store.ts";

const POLICY = `
agent: claude-code
on_behalf_of: am@team.dev
grants:
  - tool: github
    allow: [repo:read]
    deny: [pr:merge]
    require_approval: [issue:update]
budget:
  max_actions_per_hour: 100
step_up:
  window_seconds: 900
`;

function policy(): CompiledPolicy {
  const r = compilePolicyYaml(POLICY);
  if (!r.ok) throw new Error(r.error);
  return r.policy;
}

function allowedRow(over: Partial<LogEntry>): LogEntry {
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

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-explain-inputs-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("collectExplainInputs", () => {
  test("with no log: valid shape, zeros/nulls, passes coordinates through", () => {
    const inputs = collectExplainInputs({
      policy: policy(),
      agentId: "claude-code",
      tool: "github",
      action: "pr:merge",
      target: "/x",
      now: 5000,
      log: null,
      revocations: null,
      grants: null,
      approvals: { ttlSeconds: 300, rememberSeconds: 0 },
    });
    expect(inputs.tool).toBe("github");
    expect(inputs.action).toBe("pr:merge");
    expect(inputs.target).toBe("/x");
    expect(inputs.spentAgent).toBe(0);
    expect(inputs.spentUpstream).toBe(0);
    expect(inputs.revoked).toBeNull();
    expect(inputs.activeGrants).toEqual([]);
    expect(inputs.scheduleOpen).toBeNull(); // no schedule in policy
  });

  test("with a seeded log: spentAgent reflects allowed rows in the window", () => {
    const log = new RequestLog(join(dir, "req.db"));
    log.record(allowedRow({ ts: 4000 }));
    log.record(allowedRow({ ts: 4500 }));
    const inputs = collectExplainInputs({
      policy: policy(),
      agentId: "claude-code",
      tool: "github",
      action: "repo:read",
      target: null,
      now: 5000,
      log,
      revocations: null,
      grants: null,
      approvals: { ttlSeconds: 300, rememberSeconds: 0 },
    });
    expect(inputs.spentAgent).toBe(2);
    expect(inputs.spentUpstream).toBe(2);
    log.close();
  });

  test("reflects a live revocation and an active grant", () => {
    const revocations = new RevocationStore(join(dir, "rev.json"));
    revocations.revoke("claude-code", "leaked", 4000);
    const grants = new GrantStore(join(dir, "grants.json"));
    grants.mint({ agentId: "claude-code", actions: ["pr:create"], reason: "task", now: 4000, ttlMs: 60_000 });
    const inputs = collectExplainInputs({
      policy: policy(),
      agentId: "claude-code",
      tool: "github",
      action: "pr:create",
      target: null,
      now: 5000,
      log: null,
      revocations,
      grants,
      approvals: { ttlSeconds: 300, rememberSeconds: 0 },
    });
    expect(inputs.revoked).toEqual({ reason: "leaked" });
    expect(inputs.activeGrants.length).toBe(1);
    expect(inputs.activeGrants[0]!.actions).toEqual(["pr:create"]);
  });
});
