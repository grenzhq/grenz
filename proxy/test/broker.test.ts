import { test, expect, describe } from "bun:test";
import { ApprovalBroker } from "../src/approvals/broker.ts";

const input = {
  agentId: "claude-code",
  upstream: "github",
  tool: "github",
  action: "issue:update",
  target: "/repos/o/r/issues/5",
  method: "PATCH",
};

describe("ApprovalBroker", () => {
  test("approve resolves the wait promise as approved and clears the pending list", async () => {
    const broker = new ApprovalBroker(10_000);
    const { id, wait } = broker.create(input);
    expect(broker.pendingCount()).toBe(1);
    expect(broker.list()[0]!.id).toBe(id);

    expect(broker.approve(id, "cli")).toBe(true);
    const outcome = await wait;
    expect(outcome.state).toBe("approved");
    expect(outcome.decidedBy).toBe("cli");
    expect(broker.pendingCount()).toBe(0);
  });

  test("deny resolves as denied", async () => {
    const broker = new ApprovalBroker(10_000);
    const { id, wait } = broker.create(input);
    expect(broker.deny(id, "console")).toBe(true);
    const outcome = await wait;
    expect(outcome.state).toBe("denied");
    expect(outcome.decidedBy).toBe("console");
  });

  test("expires to DENY after the TTL with no decision", async () => {
    const broker = new ApprovalBroker(30);
    const { wait } = broker.create(input);
    const outcome = await wait;
    expect(outcome.state).toBe("expired");
    expect(broker.pendingCount()).toBe(0);
  });

  test("deciding an unknown or already-settled id returns false", async () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create(input);
    expect(broker.approve("apr_nope", "x")).toBe(false);
    expect(broker.approve(id, "x")).toBe(true);
    expect(broker.approve(id, "x")).toBe(false); // already settled
    expect(broker.deny(id, "x")).toBe(false);
  });

  test("drain expires everything (so held requests get a response on shutdown)", async () => {
    const broker = new ApprovalBroker(10_000);
    const a = broker.create(input);
    const b = broker.create(input);
    broker.drain();
    expect((await a.wait).state).toBe("expired");
    expect((await b.wait).state).toBe("expired");
    expect(broker.pendingCount()).toBe(0);
  });

  test("atCapacity caps concurrent pending approvals", () => {
    const broker = new ApprovalBroker(10_000, 2);
    expect(broker.atCapacity()).toBe(false);
    broker.create(input);
    expect(broker.atCapacity()).toBe(false);
    broker.create(input);
    expect(broker.atCapacity()).toBe(true); // 2 == maxPending
    expect(broker.pendingCount()).toBe(2);
  });

  test("a record carries optional approver context", () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create({ ...input, context: "check the ticket" });
    expect(broker.list()[0]!.context).toBe("check the ticket");
    expect(broker.get(id)!.context).toBe("check the ticket");
  });

  test("context is absent when not provided", () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create(input);
    expect(broker.get(id)!.context).toBeUndefined();
  });

  test("quorum 2 needs two DISTINCT approvers before it settles", async () => {
    const broker = new ApprovalBroker(10_000);
    const { id, wait } = broker.create(input, 2);
    expect(broker.get(id)!.quorum).toBe(2);
    const first = broker.approveBy(id, "alice");
    expect(first.status).toBe("recorded");
    expect(first.approvals).toBe(1);
    expect(broker.pendingCount()).toBe(1); // still blocked
    const second = broker.approveBy(id, "bob");
    expect(second.status).toBe("settled");
    expect(second.approvals).toBe(2);
    const outcome = await wait;
    expect(outcome.state).toBe("approved");
    expect(outcome.decidedBy).toBe("bob"); // the approver who reached quorum
  });

  test("the same approver twice does not reach quorum", () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create(input, 2);
    expect(broker.approveBy(id, "alice").status).toBe("recorded");
    const dup = broker.approveBy(id, "alice");
    expect(dup.status).toBe("duplicate");
    expect(dup.approvals).toBe(1);
    expect(broker.pendingCount()).toBe(1); // still blocked
  });

  test("one veto kills a quorum even after a partial approve", async () => {
    const broker = new ApprovalBroker(10_000);
    const { id, wait } = broker.create(input, 2);
    broker.approveBy(id, "alice");
    expect(broker.deny(id, "carol")).toBe(true);
    expect((await wait).state).toBe("denied");
  });

  test("quorum defaults to 1 — approve() settles on the first (regression)", () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create(input); // no quorum arg
    expect(broker.get(id)!.quorum).toBe(1);
    expect(broker.approve(id, "ops")).toBe(true); // boolean wrapper still works
  });

  test("approveBy on an unknown/settled id is not_found; approvedBy snapshot is a copy", () => {
    const broker = new ApprovalBroker(10_000);
    expect(broker.approveBy("apr_nope", "x").status).toBe("not_found");
    const { id } = broker.create(input, 2);
    broker.approveBy(id, "alice");
    const snap = broker.get(id)!;
    expect(snap.approvedBy).toEqual(["alice"]);
    snap.approvedBy.push("mutation"); // mutating the copy must not affect the broker
    expect(broker.get(id)!.approvedBy).toEqual(["alice"]);
  });

  test("cancel settles a pending approval to abandoned and resolves its wait", async () => {
    const broker = new ApprovalBroker(10_000);
    const { id, wait } = broker.create(input);
    expect(broker.list().length).toBe(1);
    expect(broker.cancel(id)).toBe(true);
    const outcome = await wait;
    expect(outcome.state).toBe("abandoned");
    expect(outcome.decidedBy).toBe(null);
    expect(broker.pendingCount()).toBe(0);
  });

  test("cancel is a no-op on an already-settled or unknown approval", () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create(input);
    expect(broker.approve(id, "ops")).toBe(true);
    expect(broker.cancel(id)).toBe(false); // already approved
    expect(broker.cancel("apr_nope")).toBe(false); // unknown id
  });

  test("list returns copies, sorted oldest-first; get returns a snapshot", () => {
    const broker = new ApprovalBroker(10_000);
    const { id } = broker.create(input);
    const snap = broker.get(id)!;
    expect(snap.state).toBe("pending");
    snap.state = "approved"; // mutating the copy must not affect the broker
    expect(broker.get(id)!.state).toBe("pending");
  });
});
