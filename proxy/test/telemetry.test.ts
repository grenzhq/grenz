import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RequestLog, type LogEntry } from "../src/log/request-log.ts";
import {
  buildPayload,
  CloudStatsReporter,
  StatsWindow,
  type StatsPayload,
  type StatsReporter,
} from "../src/telemetry/stats.ts";

let dir: string;
let log: RequestLog;

const AGENT = "claude-code-secret-agent";
const TARGET = "/repos/secret-org/secret-repo";
const ORG_TOKEN = "org_tok_SECRET_value";

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-tel-"));
  log = new RequestLog(join(dir, "requests.db"));
});
afterEach(async () => {
  log.close();
  await rm(dir, { recursive: true, force: true });
});

function entry(over: Partial<LogEntry>): LogEntry {
  return {
    ts: 1000,
    agentId: AGENT,
    upstream: "github",
    tool: "github",
    action: "repo:read",
    method: "GET",
    target: TARGET,
    decision: "allow",
    reason: "explicit_allow",
    forwarded: true,
    status: 200,
    count: 1,
    ...over,
  };
}

describe("stats payload (anonymized aggregate)", () => {
  test("aggregates by tool:action with decision counts", () => {
    log.record(entry({ action: "repo:read", decision: "allow" }));
    log.record(entry({ action: "repo:read", decision: "allow" }));
    log.record(entry({ action: "pr:merge", decision: "deny", reason: "explicit_deny" }));
    log.record(entry({ action: "issue:update", decision: "require_approval", reason: "approval_required" }));

    const payload = buildPayload(log, 0, 2000);
    const byAction = Object.fromEntries(payload.rows.map((r) => [r.action, r]));
    expect(byAction["repo:read"]?.allow).toBe(2);
    expect(byAction["pr:merge"]?.deny).toBe(1);
    expect(byAction["issue:update"]?.require_approval).toBe(1);
  });

  test("payload carries NO agent id, target/path, or any identifying field", () => {
    log.record(entry({}));
    const payload = buildPayload(log, 0, 2000);
    const json = JSON.stringify(payload);
    expect(json).not.toContain(AGENT);
    expect(json).not.toContain(TARGET);
    expect(json).not.toContain("secret-org");
    // Only these keys per row.
    for (const row of payload.rows) {
      expect(Object.keys(row).sort()).toEqual(["action", "allow", "deny", "require_approval", "tool"]);
    }
  });
});

describe("CloudStatsReporter", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("POSTs the aggregate with a bearer header; org token is NOT in the body", async () => {
    let seenUrl = "";
    let seenAuth = "";
    let seenBody = "";
    const mock = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      seenUrl = String(input);
      const headers = new Headers(init?.headers);
      seenAuth = headers.get("authorization") ?? "";
      seenBody = String(init?.body ?? "");
      return new Response("ok", { status: 200 });
    };
    globalThis.fetch = mock as unknown as typeof fetch;

    log.record(entry({}));
    const payload = buildPayload(log, 0, 2000);
    const reporter = new CloudStatsReporter("https://cloud.test/api/stats", ORG_TOKEN, () => {});
    await reporter.report(payload);

    expect(seenUrl).toBe("https://cloud.test/api/stats");
    expect(seenAuth).toBe(`Bearer ${ORG_TOKEN}`);
    const parsed = JSON.parse(seenBody) as StatsPayload;
    expect(parsed.rows.length).toBe(1);
    // The secret org token must live only in the header, never the body.
    expect(seenBody).not.toContain(ORG_TOKEN);
    expect(seenBody).not.toContain(AGENT);
    expect(seenBody).not.toContain("secret-org");
  });

  test("swallows a fetch failure (telemetry never breaks the proxy)", async () => {
    const lines: string[] = [];
    const mock = async (): Promise<Response> => {
      throw new Error("network down");
    };
    globalThis.fetch = mock as unknown as typeof fetch;
    const reporter = new CloudStatsReporter("https://cloud.test/api/stats", ORG_TOKEN, (l) => lines.push(l));
    await reporter.report(buildPayload(log, 0, 2000)); // must not throw
    expect(lines.some((l) => l.includes("failed"))).toBe(true);
    expect(lines.join("\n")).not.toContain(ORG_TOKEN);
  });
});

describe("StatsWindow", () => {
  class Recorder implements StatsReporter {
    readonly sent: StatsPayload[] = [];
    async report(payload: StatsPayload): Promise<void> {
      this.sent.push(payload);
    }
  }

  test("each report starts where the last one ended — no window is sent twice", () => {
    // The old fixed lookback re-sent [now-interval, now) after every restart,
    // and these counts are displayed as totals, so a duplicate inflates them.
    const w = new StatsWindow(log, new Recorder(), 1_000);
    expect(w.since).toBe(1_000);
    log.record(entry({ ts: 1_500 }));
    return w.flush(2_000).then((first) => {
      expect(first?.rows).toHaveLength(1);
      expect(w.since).toBe(2_000);
      return w.flush(3_000).then((second) => {
        // Nothing new happened, so nothing is re-sent.
        expect(second).toBeNull();
      });
    });
  });

  test("a late tick still covers the whole gap", async () => {
    const w = new StatsWindow(log, new Recorder(), 1_000);
    log.record(entry({ ts: 5_000 }));
    log.record(entry({ ts: 90_000 }));
    const sent = await w.flush(100_000);
    expect(sent?.rows[0]?.allow).toBe(2);
  });

  test("decisions from before the window opened are not resent", async () => {
    // A restart starts the clock at process start; a previous run's counts are
    // that run's to report. Under-reporting once beats double counting.
    log.record(entry({ ts: 500 }));
    const w = new StatsWindow(log, new Recorder(), 1_000);
    expect(await w.flush(2_000)).toBeNull();
  });

  test("an empty window sends nothing but still closes", async () => {
    const rec = new Recorder();
    const w = new StatsWindow(log, rec, 1_000);
    expect(await w.flush(2_000)).toBeNull();
    expect(rec.sent).toHaveLength(0);
    expect(w.since).toBe(2_000);
  });

  test("what it sends is still the anonymized aggregate, nothing more", async () => {
    const rec = new Recorder();
    const w = new StatsWindow(log, rec, 1_000);
    log.record(entry({ ts: 1_500 }));
    await w.flush(2_000);
    const json = JSON.stringify(rec.sent[0]);
    expect(json).not.toContain(AGENT);
    expect(json).not.toContain(TARGET);
    expect(Object.keys(rec.sent[0]!.rows[0]!).sort()).toEqual(
      ["action", "allow", "deny", "require_approval", "tool"].sort(),
    );
  });
});
