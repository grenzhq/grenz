import { test, expect, describe } from "bun:test";
import { parse as parseYaml } from "yaml";
import { setPolicySource, setTelemetry } from "../src/config/rewrite.ts";
import { checkPlaneUrl, deriveStatsUrl, safeForTerminal } from "../src/cli/connect.ts";
import { configSchema } from "../src/config/schema.ts";

const HASH = "a".repeat(64);

const COMMENTED = `# grenz.yaml — non-secret runtime config.
listen:
  host: 127.0.0.1
  port: 8787

agents:
  - id: claude-code
    token_hash: ${HASH}   # the agent's token hash
`;

const SOURCE = {
  url: "https://relay.grenz.dev/api/policy/my-agent",
  orgTokenKey: "cloud_org_token",
  refreshSeconds: 300,
  maxAgeSeconds: 3600,
};

const TELEMETRY = {
  endpoint: "https://relay.grenz.dev/api/stats",
  orgTokenKey: "cloud_org_token",
  intervalSeconds: 3600,
};

describe("setPolicySource", () => {
  test("writes a block the config schema accepts", () => {
    const r = setPolicySource(COMMENTED, SOURCE);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const parsed = configSchema.parse(parseYaml(r.yaml));
    expect(parsed.policy_source).toMatchObject({
      url: SOURCE.url,
      org_token_key: "cloud_org_token",
      refresh_seconds: 300,
      max_age_seconds: 3600,
      on_stale: "fail_closed",
    });
  });

  test("the whole point: what it writes actually loads", () => {
    // The block a person would otherwise hand-paste. If this ever produces
    // something loadConfig rejects, the command is worse than the paste.
    const r = setPolicySource(COMMENTED, SOURCE);
    expect(r.ok).toBe(true);
    if (r.ok) expect(() => configSchema.parse(parseYaml(r.yaml))).not.toThrow();
  });

  test("preserves the file's comments and other keys", () => {
    const r = setPolicySource(COMMENTED, SOURCE);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.yaml).toContain("# grenz.yaml — non-secret runtime config.");
    expect(r.yaml).toContain("# the agent's token hash");
    expect(r.yaml).toContain("port: 8787");
    expect(r.yaml).toContain(HASH);
  });

  test("refuses to replace an existing policy_source", () => {
    const once = setPolicySource(COMMENTED, SOURCE);
    expect(once.ok).toBe(true);
    if (!once.ok) return;
    const twice = setPolicySource(once.yaml, { ...SOURCE, url: "https://other.example/api/policy/x" });
    expect(twice.ok).toBe(false);
    if (!twice.ok) expect(twice.error).toContain("--force");
  });

  test("a pinned public_key survives a refused overwrite", () => {
    // The reason the refusal exists: replacing a pinned block with an unpinned
    // one downgrades verified distribution to trusted-transport, silently.
    const pinned = `agents:
  - id: a
    token_hash: ${HASH}
policy_source:
  url: https://relay.grenz.dev/api/policy/a
  public_key:
    - AAAAC3NzaC1lZDI1NTE5
`;
    const r = setPolicySource(pinned, SOURCE);
    expect(r.ok).toBe(false);
  });

  test("--force replaces it", () => {
    const once = setPolicySource(COMMENTED, SOURCE);
    expect(once.ok).toBe(true);
    if (!once.ok) return;
    const twice = setPolicySource(once.yaml, { ...SOURCE, url: "https://other.example/api/policy/x" }, true);
    expect(twice.ok).toBe(true);
    if (twice.ok) {
      expect(twice.yaml).toContain("https://other.example/api/policy/x");
      expect(twice.yaml).not.toContain("relay.grenz.dev");
    }
  });

  test("the explanation sits above the key, not inside the block", () => {
    // Regressed once: a comment on the value node lands after `policy_source:`,
    // which reads as machine output. The file has to still look hand-written.
    const r = setPolicySource(COMMENTED, SOURCE);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const comment = r.yaml.indexOf("# Where this proxy pulls its policy");
    const key = r.yaml.indexOf("policy_source:");
    expect(comment).toBeGreaterThan(-1);
    expect(comment).toBeLessThan(key);
  });

  test("pins public keys when given, and requires a signed bundle", () => {
    const r = setPolicySource(COMMENTED, { ...SOURCE, publicKeys: ["k1", "k2"] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(configSchema.parse(parseYaml(r.yaml)).policy_source!.public_key).toEqual(["k1", "k2"]);
  });

  test("no keys given means no public_key line, not an empty one", () => {
    const r = setPolicySource(COMMENTED, { ...SOURCE, publicKeys: [] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.yaml).not.toContain("public_key");
  });

  test("fails closed on a malformed file", () => {
    const r = setPolicySource("agents: [\n  - broken", SOURCE);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("invalid grenz.yaml");
  });
});

describe("setTelemetry", () => {
  test("writes a block the schema accepts, with enabled: true", () => {
    const r = setTelemetry(COMMENTED, TELEMETRY);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const parsed = configSchema.parse(parseYaml(r.yaml));
    expect(parsed.telemetry).toMatchObject({
      enabled: true,
      endpoint: TELEMETRY.endpoint,
      org_token_key: "cloud_org_token",
      interval_seconds: 3600,
    });
  });

  test("says in the file what it sends", () => {
    const r = setTelemetry(COMMENTED, TELEMETRY);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.yaml).toContain("never a target");
  });

  test("refuses to replace an existing block without force", () => {
    const once = setTelemetry(COMMENTED, TELEMETRY);
    expect(once.ok).toBe(true);
    if (!once.ok) return;
    expect(setTelemetry(once.yaml, TELEMETRY).ok).toBe(false);
    expect(setTelemetry(once.yaml, TELEMETRY, true).ok).toBe(true);
  });

  test("connecting without --telemetry writes no telemetry block", () => {
    // Telemetry is egress and opt-in. A connect that switched it on as a side
    // effect would be turning on data flow nobody asked for.
    const r = setPolicySource(COMMENTED, SOURCE);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.yaml).not.toContain("telemetry:");
      expect(configSchema.parse(parseYaml(r.yaml)).telemetry).toBeUndefined();
    }
  });
});

describe("checkPlaneUrl", () => {
  const cases: ReadonlyArray<readonly [string, boolean, string]> = [
    ["https://relay.grenz.dev/api/policy/a", true, "https is the normal case"],
    ["http://localhost:3000/api/policy/a", true, "http on localhost is local dev"],
    ["http://127.0.0.1:3000/api/policy/a", true, "loopback by address too"],
    ["http://relay.grenz.dev/api/policy/a", false, "plain http off-localhost leaks the token"],
    ["ftp://relay.grenz.dev/x", false, "unsupported scheme"],
    ["relay.grenz.dev/api/policy/a", false, "not a URL at all"],
    ["", false, "empty"],
  ];

  for (const [url, ok, why] of cases) {
    test(`${ok ? "accepts" : "refuses"} ${url || "(empty)"} — ${why}`, () => {
      expect(checkPlaneUrl(url).ok).toBe(ok);
    });
  }

  test("the http refusal says why, not just no", () => {
    const r = checkPlaneUrl("http://relay.grenz.dev/api/policy/a");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("org token");
  });
});

describe("deriveStatsUrl", () => {
  test("same origin, /api/stats", () => {
    expect(deriveStatsUrl(new URL("https://relay.grenz.dev/api/policy/my-agent"))).toBe(
      "https://relay.grenz.dev/api/stats",
    );
  });

  test("keeps a mount prefix", () => {
    expect(deriveStatsUrl(new URL("https://x.dev/grenz/api/policy/a"))).toBe("https://x.dev/grenz/api/stats");
  });

  test("keeps a non-default port", () => {
    expect(deriveStatsUrl(new URL("http://localhost:3000/api/policy/a"))).toBe("http://localhost:3000/api/stats");
  });

  test("an unrecognized path yields nothing rather than a guess", () => {
    // Guessing here would point telemetry at something that is not the plane.
    expect(deriveStatsUrl(new URL("https://relay.grenz.dev/policies/a"))).toBeUndefined();
  });

  test("an agent id containing the marker does not confuse it", () => {
    expect(deriveStatsUrl(new URL("https://x.dev/api/policy/api/policy/weird"))).toBe("https://x.dev/api/policy/api/stats");
  });
});

describe("safeForTerminal", () => {
  test("strips the control characters that would repaint the line", () => {
    // The agent name comes from the plane and is printed to a terminal, where
    // escapes are instructions rather than text.
    expect(safeForTerminal("my-agent")).toBe("my-agent");
    expect(safeForTerminal("\u001b[2Kfake \u001b[32m✓ connected as admin")).toBe("[2Kfake [32m✓ connected as admin");
    expect(safeForTerminal("a\rb\nc\u0007")).toBe("abc");
  });

  test("bounds the length so one field cannot flood the screen", () => {
    expect(safeForTerminal("x".repeat(500))).toHaveLength(80);
  });

  test("leaves ordinary punctuation and unicode alone", () => {
    expect(safeForTerminal("claude-code_mac.1 — ok")).toBe("claude-code_mac.1 — ok");
  });
});
