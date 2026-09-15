import { test, expect, describe } from "bun:test";
import { configSchema } from "../src/config/schema.ts";

const base = { agents: [{ id: "a", token_hash: "a".repeat(64) }] };
function withPs(over: Record<string, unknown> = {}) {
  return configSchema.parse({ ...base, policy_source: { url: "https://p.example/b", ...over } }).policy_source!;
}

describe("policy_source signing config", () => {
  test("defaults: no keys, refresh 0, on_stale warn", () => {
    const ps = withPs();
    expect(ps.public_key).toEqual([]);
    expect(ps.refresh_seconds).toBe(0);
    expect(ps.on_stale).toBe("warn");
    expect(ps.max_age_seconds).toBeUndefined();
  });
  test("public_key accepts a list (rotation)", () => {
    expect(withPs({ public_key: ["k1", "k2"] }).public_key).toEqual(["k1", "k2"]);
  });
  test("on_stale rejects a bad value", () => {
    expect(() => withPs({ on_stale: "explode" })).toThrow();
  });
  test("refresh_seconds must be 0 or >= 30", () => {
    expect(() => withPs({ refresh_seconds: 5 })).toThrow();
    expect(withPs({ refresh_seconds: 0 }).refresh_seconds).toBe(0);
    expect(withPs({ refresh_seconds: 300 }).refresh_seconds).toBe(300);
  });
  test("max_age_seconds is bounded", () => {
    expect(() => withPs({ max_age_seconds: 5, refresh_seconds: 300 })).toThrow();
    expect(withPs({ max_age_seconds: 3600, refresh_seconds: 300 }).max_age_seconds).toBe(3600);
  });
  test("unknown keys are rejected (strict)", () => {
    expect(() => withPs({ sign_it_please: true })).toThrow();
  });
  test("max_age_seconds without a refresh loop is rejected, not silently inert", () => {
    // With refresh_seconds: 0 the proxy never re-pulls, so the staleness bound
    // could never be re-evaluated or cleared -- accepting it would promise an
    // enforcement that does not exist.
    expect(() => withPs({ max_age_seconds: 3600 })).toThrow(/refresh_seconds/);
    expect(() => withPs({ max_age_seconds: 3600, refresh_seconds: 0 })).toThrow(/refresh_seconds/);
    expect(withPs({ max_age_seconds: 3600, refresh_seconds: 300 }).max_age_seconds).toBe(3600);
  });
  test("on_stale: fail_closed requires a staleness bound to act on", () => {
    expect(() => withPs({ on_stale: "fail_closed", refresh_seconds: 300 })).toThrow(/max_age_seconds/);
    expect(
      withPs({ on_stale: "fail_closed", refresh_seconds: 300, max_age_seconds: 3600 }).on_stale,
    ).toBe("fail_closed");
  });
});

describe("policy_source revocation config", () => {
  const rev = "https://p.example/rev";

  test("defaults: revocation_refresh_seconds 0, on_revocation_stale warn", () => {
    const ps = withPs({ public_key: ["k"], revocation_url: rev });
    expect(ps.revocation_refresh_seconds).toBe(0);
    expect(ps.on_revocation_stale).toBe("warn");
    expect(ps.revocation_max_age_seconds).toBeUndefined();
  });

  test("full valid revocation config with fail_closed", () => {
    const ps = withPs({
      public_key: ["k"],
      revocation_url: rev,
      revocation_refresh_seconds: 60,
      revocation_max_age_seconds: 900,
      on_revocation_stale: "fail_closed",
    });
    expect(ps.revocation_url).toBe(rev);
    expect(ps.revocation_refresh_seconds).toBe(60);
    expect(ps.revocation_max_age_seconds).toBe(900);
    expect(ps.on_revocation_stale).toBe("fail_closed");
  });

  test("revocation_url without a pinned key is rejected (an unsigned channel can un-revoke the fleet)", () => {
    expect(() => withPs({ revocation_url: rev })).toThrow(/public_key/);
  });

  test("revocation_max_age_seconds requires revocation_refresh_seconds > 0", () => {
    expect(() => withPs({ public_key: ["k"], revocation_url: rev, revocation_max_age_seconds: 900 })).toThrow(
      /revocation_refresh_seconds/,
    );
  });

  test("on_revocation_stale: fail_closed requires revocation_max_age_seconds", () => {
    expect(() =>
      withPs({ public_key: ["k"], revocation_url: rev, revocation_refresh_seconds: 60, on_revocation_stale: "fail_closed" }),
    ).toThrow(/revocation_max_age_seconds/);
  });

  test("revocation_refresh_seconds must be 0 or >= 30", () => {
    expect(() => withPs({ public_key: ["k"], revocation_url: rev, revocation_refresh_seconds: 5 })).toThrow();
    expect(withPs({ public_key: ["k"], revocation_url: rev, revocation_refresh_seconds: 30 }).revocation_refresh_seconds).toBe(30);
  });

  test("revocation_max_age_seconds shorter than the refresh interval is rejected", () => {
    // Staleness is only checked once per refresh, so a shorter bound cannot be
    // enforced tightly.
    expect(() =>
      withPs({ public_key: ["k"], revocation_url: rev, revocation_refresh_seconds: 300, revocation_max_age_seconds: 60 }),
    ).toThrow(/revocation_max_age_seconds/);
    // Equal is allowed.
    expect(
      withPs({ public_key: ["k"], revocation_url: rev, revocation_refresh_seconds: 300, revocation_max_age_seconds: 300 })
        .revocation_max_age_seconds,
    ).toBe(300);
  });
});

/**
 * The org token travels the policy_source URL, and whatever comes back is the
 * policy this proxy enforces. Over plain http an on-path attacker gets both
 * halves: the token, and the ability to answer with `allow: ["*"]`. Signing is
 * optional here, so nothing else catches it.
 *
 * `grenz connect` already refused to WRITE such a config. These cover the other
 * half — refusing to RUN a hand-edited one.
 */
describe("policy_source: plain http is refused off localhost", () => {
  const withUrl = (url: string) => configSchema.safeParse({ ...base, policy_source: { url } });

  test("https is accepted", () => {
    expect(withUrl("https://relay.grenz.dev/api/policy/x").success).toBe(true);
  });

  test("http off-localhost is refused", () => {
    const r = withUrl("http://relay.grenz.dev/api/policy/x");
    expect(r.success).toBe(false);
    if (!r.success) expect(r.error.issues[0]!.message).toContain("must be https");
  });

  test("http on localhost is accepted — a dev plane on the same machine", () => {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      expect(withUrl(`http://${host}:3000/api/policy/x`).success).toBe(true);
    }
  });

  test("a non-http scheme is refused", () => {
    expect(withUrl("ftp://relay.grenz.dev/api/policy/x").success).toBe(false);
  });

  test("revocation_url gets the same rule", () => {
    const r = configSchema.safeParse({
      ...base,
      policy_source: {
        url: "https://relay.grenz.dev/api/policy/x",
        public_key: ["k"],
        revocation_url: "http://relay.grenz.dev/api/revocations",
      },
    });
    expect(r.success).toBe(false);
  });
});
