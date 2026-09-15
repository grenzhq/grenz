import { test, expect, describe } from "bun:test";
import { startDeviceFlow, pollUntilReady, type DeviceStart } from "../src/cli/device-flow.ts";

const PLANE = "https://relay.grenz.dev";

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** A clock that only moves when the code under test sleeps. */
function fakeClock() {
  let t = 1_000_000;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
    advance: (ms: number) => {
      t += ms;
    },
  };
}

const START: DeviceStart = {
  deviceCode: "grzd_abc",
  userCode: "QXTZ4-F9KM2",
  verificationUri: `${PLANE}/activate`,
  expiresInSeconds: 900,
  intervalSeconds: 5,
};

describe("startDeviceFlow", () => {
  test("returns the pair and the link", async () => {
    const r = await startDeviceFlow(PLANE, {
      fetch: async () =>
        jsonRes({
          device_code: "grzd_x",
          user_code: "QXTZ4-F9KM2",
          verification_uri: `${PLANE}/activate`,
          expires_in: 900,
          interval: 5,
        }),
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.start).toMatchObject({ deviceCode: "grzd_x", userCode: "QXTZ4-F9KM2", intervalSeconds: 5 });
  });

  test("a plane missing its site URL says so, not just 503", async () => {
    const r = await startDeviceFlow(PLANE, { fetch: async () => jsonRes({ error: "nope" }, 503) });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("NEXT_PUBLIC_SITE_URL");
  });

  test("an unreachable plane is a clear message, not a stack trace", async () => {
    const r = await startDeviceFlow(PLANE, {
      fetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("cannot reach");
  });

  test("a response missing any half of the pair is refused", async () => {
    const r = await startDeviceFlow(PLANE, { fetch: async () => jsonRes({ user_code: "QXTZ4-F9KM2" }) });
    expect(r.ok).toBe(false);
  });

  test("the plane cannot talk the CLI into a 1ms poll or an eternal one", async () => {
    // A hostile or broken plane must not be able to make this hammer or hang.
    const fast = await startDeviceFlow(PLANE, {
      fetch: async () =>
        jsonRes({ device_code: "d", user_code: "u", verification_uri: "v", interval: 0, expires_in: 999_999 }),
    });
    expect(fast.ok).toBe(true);
    if (fast.ok) {
      expect(fast.start.intervalSeconds).toBeGreaterThanOrEqual(1);
      expect(fast.start.expiresInSeconds).toBeLessThanOrEqual(1800);
    }
  });
});

describe("pollUntilReady", () => {
  test("waits through pending, then returns the token", async () => {
    const clock = fakeClock();
    let calls = 0;
    const r = await pollUntilReady(PLANE, START, {
      now: clock.now,
      sleep: clock.sleep,
      fetch: async () => {
        calls++;
        if (calls < 3) return jsonRes({ status: "pending", interval: 5 });
        return jsonRes({
          status: "ready",
          token: "grz_minted",
          agent: "my-agent",
          policy_url: `${PLANE}/api/policy/my-agent`,
          stats_url: `${PLANE}/api/stats`,
        });
      },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.ready).toMatchObject({ token: "grz_minted", agent: "my-agent" });
    expect(calls).toBe(3);
  });

  test("stops on the plane's own deadline rather than polling forever", async () => {
    const clock = fakeClock();
    let calls = 0;
    const r = await pollUntilReady(PLANE, { ...START, expiresInSeconds: 30 }, {
      now: clock.now,
      sleep: clock.sleep,
      fetch: async () => {
        calls++;
        return jsonRes({ status: "pending" });
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("timed out");
    // 30s at a 5s interval — bounded, not unbounded.
    expect(calls).toBeLessThanOrEqual(7);
  });

  const verdicts: ReadonlyArray<readonly [string, number, string]> = [
    ["expired", 410, "expired"],
    ["consumed", 410, "already used"],
    ["unknown", 404, "does not recognize"],
  ];
  for (const [status, code, phrase] of verdicts) {
    test(`"${status}" stops immediately and says why`, async () => {
      const clock = fakeClock();
      const r = await pollUntilReady(PLANE, START, {
        now: clock.now,
        sleep: clock.sleep,
        fetch: async () => jsonRes({ status }, code),
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain(phrase);
    });
  }

  test("survives a few network blips, then succeeds", async () => {
    const clock = fakeClock();
    let calls = 0;
    const r = await pollUntilReady(PLANE, START, {
      now: clock.now,
      sleep: clock.sleep,
      fetch: async () => {
        if (++calls <= 3) throw new TypeError("fetch failed");
        return jsonRes({
          status: "ready",
          token: "t",
          agent: "a",
          policy_url: `${PLANE}/api/policy/a`,
          stats_url: `${PLANE}/api/stats`,
        });
      },
    });
    expect(r.ok).toBe(true);
  });

  test("gives up after sustained network failure instead of spinning", async () => {
    const clock = fakeClock();
    const r = await pollUntilReady(PLANE, START, {
      now: clock.now,
      sleep: clock.sleep,
      fetch: async () => {
        throw new TypeError("fetch failed");
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("lost contact");
  });

  test("an approval with a missing token is refused, not half-applied", async () => {
    // The caller writes config on `ok`, so an incomplete ready must not be ok.
    const clock = fakeClock();
    const r = await pollUntilReady(PLANE, START, {
      now: clock.now,
      sleep: clock.sleep,
      fetch: async () => jsonRes({ status: "ready", agent: "a", policy_url: "u" }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("incomplete");
  });
});
