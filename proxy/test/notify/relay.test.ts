import { test, expect } from "bun:test";
import { RelayChannel, type RelayBrokerHandle, type RelayOptions } from "../../src/notify/relay.ts";
import { ApprovalBroker, type ApprovalRecord } from "../../src/approvals/broker.ts";

function record(over: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    id: "apr_1", agentId: "nightly", upstream: "github", tool: "github",
    action: "repo:push", target: "acme/app", method: "POST", context: "force push",
    requestedAt: 1000, expiresAt: 301000, state: "pending", decidedBy: null,
    quorum: 1, approvedBy: [], ...over,
  };
}

/** A broker spy that records settle calls. */
function spyBroker(): { handle: RelayBrokerHandle; calls: string[] } {
  const calls: string[] = [];
  const handle: RelayBrokerHandle = {
    approveBy: (id, by) => { calls.push(`approve:${id}:${by}`); return { status: "settled", approvals: 1, quorum: 1 }; },
    deny: (id, by) => { calls.push(`deny:${id}:${by}`); return true; },
  };
  return { handle, calls };
}

/** Capture every fetch call; reply per a scripted queue. */
function fakeFetch(replies: Array<{ ok?: boolean; status?: number; json?: unknown; throws?: boolean }>): {
  impl: typeof fetch;
  seen: Array<{ url: string; init?: RequestInit }>;
} {
  const seen: Array<{ url: string; init?: RequestInit }> = [];
  let i = 0;
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(url), init });
    const r = replies[Math.min(i, replies.length - 1)] ?? {};
    i += 1;
    if (r.throws) throw new Error("network");
    return {
      ok: r.ok ?? true,
      status: r.status ?? 200,
      json: async () => r.json ?? {},
    } as Response;
  }) as unknown as typeof fetch;
  return { impl, seen };
}

const opts = (over: Partial<RelayOptions> = {}): RelayOptions => ({
  url: "https://relay.test", token: "relay-secret-token", reconnectDelayMs: 1, ...over,
});

test("approvalRequested POSTs metadata-only to /v1/approvals with a bearer header", async () => {
  const { handle } = spyBroker();
  const { impl, seen } = fakeFetch([{ ok: true, json: { status: "pending" } }, { ok: true, json: { status: "approved", resolved_by: "sam" } }]);
  // clock jumps past expiry after the first poll so the loop terminates for the test
  let t = 500; const clock = (): number => (t += 300000);
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 10 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20); // let the background poll settle

  const post = seen.find((s) => s.url === "https://relay.test/v1/approvals" && s.init?.method === "POST");
  expect(post).toBeTruthy();
  const headers = post!.init!.headers as Record<string, string>;
  expect(headers.authorization).toBe("Bearer relay-secret-token");
  const body = JSON.parse(post!.init!.body as string);
  expect(body).toEqual({
    id: "apr_1", agentId: "nightly", upstream: "github", tool: "github",
    action: "repo:push", target: "acme/app", method: "POST", context: "force push",
    requestedAt: 1000, expiresAt: 301000,
  });
  // No credential-ish keys anywhere in the POST body.
  const raw = post!.init!.body as string;
  for (const bad of ["token", "secret", "credential", "password", "authorization", "Bearer"]) {
    expect(raw.toLowerCase()).not.toContain(bad.toLowerCase());
  }
});

test("approvalRequested that fails to POST never polls and never settles (fail-closed)", async () => {
  const { handle, calls } = spyBroker();
  const { impl, seen } = fakeFetch([{ throws: true }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20);
  expect(calls).toEqual([]);                       // broker untouched → local TTL denies
  expect(seen.filter((s) => s.init?.method === "GET")).toEqual([]); // no poll started
});

test("approvalRequested treats a non-2xx create as fail-closed", async () => {
  const { handle, calls } = spyBroker();
  const { impl, seen } = fakeFetch([{ ok: false, status: 500 }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20);
  expect(calls).toEqual([]);
  expect(seen.filter((s) => s.init?.method === "GET")).toEqual([]);
});

test("an approved verdict on the first poll settles the broker approved", async () => {
  const { handle, calls } = spyBroker();
  const { impl } = fakeFetch([
    { ok: true, json: {} },                                          // POST create
    { ok: true, json: { status: "approved", resolved_by: "sam" } }, // first GET
  ]);
  const clock = (): number => 500; // stays < expiresAt=301000 until settled
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20);
  expect(calls).toEqual(["approve:apr_1:sam"]);
});

test("a denied verdict settles the broker denied", async () => {
  const { handle, calls } = spyBroker();
  const { impl } = fakeFetch([
    { ok: true, json: {} },
    { ok: true, json: { status: "denied", resolved_by: "lee" } },
  ]);
  const clock = (): number => 500;
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20);
  expect(calls).toEqual(["deny:apr_1:lee"]);
});

test("a verdict on a LATER poll window still settles (reconnect covers the TTL)", async () => {
  const { handle, calls } = spyBroker();
  const { impl } = fakeFetch([
    { ok: true, json: {} },                                          // POST
    { ok: true, json: { status: "pending" } },                      // GET window 1
    { ok: true, json: { status: "pending" } },                      // GET window 2
    { ok: true, json: { status: "approved", resolved_by: "sam" } }, // GET window 3
  ]);
  const clock = (): number => 500; // never expires during the test
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(30);
  expect(calls).toEqual(["approve:apr_1:sam"]);
});

test("a malformed verdict is treated as pending and never approves", async () => {
  const { handle, calls } = spyBroker();
  const { impl } = fakeFetch([
    { ok: true, json: {} },                        // POST
    { ok: true, json: { status: "yes-please" } },  // garbage → pending
    { ok: true, json: { nope: true } },            // garbage → pending
  ]);
  // clock advances so the loop terminates after two GET windows without approving
  let n = 0; const clock = (): number => { n += 1; return n <= 3 ? 500 : 400000; };
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20);
  expect(calls).toEqual([]); // never settled → local TTL denies
});

test("no verdict before the deadline never settles (deny-by-default)", async () => {
  const { handle, calls } = spyBroker();
  const { impl } = fakeFetch([{ ok: true, json: {} }, { ok: true, json: { status: "pending" } }]);
  let n = 0; const clock = (): number => { n += 1; return n <= 2 ? 500 : 400000; };
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(20);
  expect(calls).toEqual([]);
});

test("a network error mid-poll reconnects rather than settling", async () => {
  const { handle, calls } = spyBroker();
  const { impl } = fakeFetch([
    { ok: true, json: {} },                                          // POST
    { throws: true },                                               // GET window 1 → network error
    { ok: true, json: { status: "approved", resolved_by: "sam" } }, // GET window 2
  ]);
  const clock = (): number => 500;
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(30);
  expect(calls).toEqual(["approve:apr_1:sam"]);
});

test("approvalResolved POSTs the final state to /resolution", async () => {
  const { handle } = spyBroker();
  const { impl, seen } = fakeFetch([{ ok: true, json: {} }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl }), handle);
  await ch.approvalResolved(record(), { state: "expired", decidedBy: null });
  const res = seen.find((s) => s.url === "https://relay.test/v1/approvals/apr_1/resolution");
  expect(res).toBeTruthy();
  expect(res!.init?.method).toBe("POST");
  expect(JSON.parse(res!.init!.body as string)).toEqual({ status: "expired" });
});

test("approvalResolved aborts an in-flight poll so it stops reconnecting", async () => {
  const { handle, calls } = spyBroker();
  // POST ok, then GETs keep returning pending forever
  const { impl } = fakeFetch([{ ok: true, json: {} }, { ok: true, json: { status: "pending" } }]);
  const clock = (): number => 500; // would poll forever without the abort
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock, pollWindowMs: 5 }), handle);
  await ch.approvalRequested(record(), "hint");
  await Bun.sleep(10);
  await ch.approvalResolved(record(), { state: "expired", decidedBy: null });
  await Bun.sleep(15);
  expect(calls).toEqual([]); // never settled by the relay; loop is torn down
});

test("approvalResolved never throws when the relay is unreachable", async () => {
  const { handle } = spyBroker();
  const { impl } = fakeFetch([{ throws: true }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl }), handle);
  await expect(ch.approvalResolved(record(), { state: "denied", decidedBy: "lee" })).resolves.toBeUndefined();
});

test("end-to-end: a real broker forwards after the relay returns approved", async () => {
  // A fake relay: create returns 202; the first GET returns approved.
  let gets = 0;
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/v1/approvals") return new Response("{}", { status: 202 });
      if (req.method === "GET" && url.pathname.startsWith("/v1/approvals/")) {
        gets += 1;
        return Response.json({ status: "approved", resolved_by: "on-call" });
      }
      return new Response("no", { status: 404 });
    },
  });
  try {
    const broker = new ApprovalBroker(300_000, 100);
    const ch = new RelayChannel({ url: `http://localhost:${server.port}`, token: "t", pollWindowMs: 5, reconnectDelayMs: 1 }, broker);
    const { id, wait } = broker.create({
      agentId: "nightly", upstream: "github", tool: "github",
      action: "repo:push", target: "acme/app", method: "POST",
    });
    const rec = broker.get(id)!;
    await ch.approvalRequested(rec, `grenz approve ${id}`);
    const outcome = await wait;
    expect(outcome.state).toBe("approved");
    expect(outcome.decidedBy).toBe("on-call");
    expect(gets).toBeGreaterThanOrEqual(1);
  } finally {
    server.stop(true);
  }
});

test("tripwireTripped POSTs a metadata-only alarm to /v1/alarms with a bearer header", async () => {
  const { handle } = spyBroker();
  const { impl, seen } = fakeFetch([{ ok: true }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock: () => 4242 }), handle);
  await ch.tripwireTripped("lead-agent", "repo:delete", "acme/app", "no deletes");

  const post = seen.find((s) => s.url === "https://relay.test/v1/alarms" && s.init?.method === "POST");
  expect(post).toBeTruthy();
  const headers = post!.init!.headers as Record<string, string>;
  expect(headers.authorization).toBe("Bearer relay-secret-token");
  const body = JSON.parse(post!.init!.body as string);
  expect(body).toEqual({
    kind: "tripwire", agentId: "lead-agent", action: "repo:delete",
    target: "acme/app", note: "no deletes", at: 4242,
  });
  // No credential-ish material rides along in the alarm body.
  const raw = (post!.init!.body as string).toLowerCase();
  for (const bad of ["secret", "credential", "password", "bearer", "ghp_"]) {
    expect(raw).not.toContain(bad.toLowerCase());
  }
});

test("decoyTripped POSTs a metadata-only alarm to /v1/alarms", async () => {
  const { handle } = spyBroker();
  const { impl, seen } = fakeFetch([{ ok: true }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl, clock: () => 99 }), handle);
  await ch.decoyTripped("upstream", "del_abc", "honeypot", "/u/honeypot/x");

  const post = seen.find((s) => s.url === "https://relay.test/v1/alarms" && s.init?.method === "POST");
  expect(post).toBeTruthy();
  const body = JSON.parse(post!.init!.body as string);
  expect(body).toEqual({
    kind: "decoy", decoy: "upstream", actorId: "del_abc",
    upstream: "honeypot", path: "/u/honeypot/x", at: 99,
  });
});

test("a failed alarm POST never throws into the pipeline (local revoke stands)", async () => {
  const { handle } = spyBroker();
  const { impl } = fakeFetch([{ throws: true }]);
  const ch = new RelayChannel(opts({ fetchImpl: impl }), handle);
  // Neither call rejects, even though the network fails.
  await ch.tripwireTripped("a", "x:y", null, null);
  await ch.decoyTripped("token", "a", "up", "/p");
  expect(true).toBe(true);
});
