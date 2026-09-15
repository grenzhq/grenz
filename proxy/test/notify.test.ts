import { test, expect, describe, afterEach } from "bun:test";
import { SlackNotifier } from "../src/notify/slack.ts";
import type { ApprovalRecord } from "../src/approvals/broker.ts";

const record: ApprovalRecord = {
  id: "apr_1",
  agentId: "claude-code",
  upstream: "github",
  tool: "github",
  action: "issue:update",
  target: "/repos/o/r/issues/5",
  method: "PATCH",
  requestedAt: 1000,
  expiresAt: 1000 + 300_000,
  state: "pending",
  decidedBy: null,
  quorum: 1,
  approvedBy: [],
};

const WEBHOOK = "https://hooks.slack.test/secret-webhook-path";
const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("SlackNotifier", () => {
  test("posts payload with action + approve hint; never echoes the webhook URL", async () => {
    let seenUrl = "";
    let seenBody = "";
    const mock = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      seenUrl = String(input);
      seenBody = String(init?.body ?? "");
      return new Response("ok", { status: 200 });
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    const notifier = new SlackNotifier(WEBHOOK, () => {});
    await notifier.approvalRequested(record, "grenz approve apr_1");

    expect(seenUrl).toBe(WEBHOOK);
    const payload = JSON.parse(seenBody) as { text: string };
    expect(payload.text).toContain("issue:update");
    expect(payload.text).toContain("grenz approve apr_1");
    // The secret webhook URL must not appear in the message text.
    expect(payload.text).not.toContain("secret-webhook-path");
  });

  test("notes distinct approvers when the record needs a quorum", async () => {
    let seenBody = "";
    const mock = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      seenBody = String(init?.body ?? "");
      return new Response("ok", { status: 200 });
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    const notifier = new SlackNotifier(WEBHOOK, () => {});
    await notifier.approvalRequested({ ...record, quorum: 2, approvedBy: [] }, "grenz approve apr_1");

    const payload = JSON.parse(seenBody) as { text: string };
    expect(payload.text).toContain("2");
    expect(payload.text.toLowerCase()).toContain("approver");
  });

  test("includes the approver context when the record carries one", async () => {
    let seenBody = "";
    const mock = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      seenBody = String(init?.body ?? "");
      return new Response("ok", { status: 200 });
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    const notifier = new SlackNotifier(WEBHOOK, () => {});
    await notifier.approvalRequested(
      { ...record, context: "confirm the change is on a tracked ticket" },
      "grenz approve apr_1",
    );

    const payload = JSON.parse(seenBody) as { text: string };
    expect(payload.text).toContain("confirm the change is on a tracked ticket");
  });

  test("swallows a fetch failure (never throws into the pipeline)", async () => {
    const mock = async (): Promise<Response> => {
      throw new Error("network down");
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    const lines: string[] = [];
    const notifier = new SlackNotifier(WEBHOOK, (l) => lines.push(l));
    await notifier.approvalRequested(record, "grenz approve apr_1"); // must not throw
    expect(lines.some((l) => l.includes("failed"))).toBe(true);
    // Even the operational line must not leak the webhook URL.
    expect(lines.join("\n")).not.toContain("secret-webhook-path");
  });

  test("approvalResolved posts an outcome follow-up; never echoes the webhook", async () => {
    let seenUrl = "";
    let seenBody = "";
    const mock = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      seenUrl = String(input);
      seenBody = String(init?.body ?? "");
      return new Response("ok", { status: 200 });
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    const notifier = new SlackNotifier(WEBHOOK, () => {});
    await notifier.approvalResolved!({ ...record }, { state: "approved", decidedBy: "ops" });

    expect(seenUrl).toBe(WEBHOOK);
    const payload = JSON.parse(seenBody) as { text: string };
    expect(payload.text).toContain("Approved");
    expect(payload.text).toContain("ops");
    expect(payload.text).toContain("issue:update");
    expect(payload.text).not.toContain("secret-webhook-path");
  });

  test("approvalResolved renders each outcome and swallows a fetch failure", async () => {
    const seen: string[] = [];
    const mock = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      seen.push((JSON.parse(String(init?.body ?? "{}")) as { text: string }).text);
      throw new Error("network");
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    const notifier = new SlackNotifier(WEBHOOK, () => {});
    // None of these may throw despite the fetch failure.
    await notifier.approvalResolved!(record, { state: "denied", decidedBy: "ops" });
    await notifier.approvalResolved!(record, { state: "expired", decidedBy: null });
    await notifier.approvalResolved!(record, { state: "abandoned", decidedBy: null });

    expect(seen[0]).toContain("Denied");
    expect(seen[1]).toContain("Expired");
    expect(seen[2]).toContain("Withdrawn");
    expect(seen.join("\n")).not.toContain("secret-webhook-path");
  });
});
