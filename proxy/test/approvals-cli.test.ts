import { test, expect, describe } from "bun:test";
import { fmtApproval } from "../src/cli/approvals.ts";
import type { ApprovalRecord } from "../src/approvals/broker.ts";

const base: ApprovalRecord = {
  id: "apr_x",
  agentId: "claude-code",
  upstream: "github",
  tool: "github",
  action: "issue:update",
  target: "/repos/o/r/issues/5",
  method: "PATCH",
  requestedAt: 0,
  expiresAt: Date.now() + 300_000,
  state: "pending",
  decidedBy: null,
  quorum: 1,
  approvedBy: [],
};

describe("fmtApproval", () => {
  test("shows approver context on its own line when present", () => {
    const out = fmtApproval({ ...base, context: "confirm the change is on a tracked ticket" });
    expect(out).toContain("confirm the change is on a tracked ticket");
    expect(out.split("\n").length).toBe(2); // header line + context line
  });

  test("no context -> a single line", () => {
    const out = fmtApproval(base);
    expect(out.split("\n").length).toBe(1);
    expect(out).toContain("apr_x");
    expect(out).toContain("github:issue:update");
  });

  test("shows N/quorum progress when quorum > 1", () => {
    const out = fmtApproval({ ...base, quorum: 2, approvedBy: ["alice"] });
    expect(out).toContain("1/2");
  });

  test("no quorum progress marker for quorum 1", () => {
    expect(fmtApproval(base)).not.toContain("/1");
  });
});
