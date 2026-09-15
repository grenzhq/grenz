import { test, expect, describe } from "bun:test";
import { buildReport, worstStatus, type DoctorInputs, type Check } from "../src/doctor/checks.ts";

const OK: DoctorInputs = {
  configError: null,
  upstreams: { github: { type: "github", decoy: false, credential: "gh_token" } },
  policyError: null,
  grantCount: 2,
  grantTools: ["github"],
  vaultError: null,
  credentialPresent: { gh_token: true },
  adminTokenPresent: true,
  agents: [],
  now: 100 * 86_400_000,
  socket: null,
  port: 8787,
  portInUse: false,
  integrations: { slackWebhook: false, llmApiKey: true, telemetryEnabled: false },
  planeKeys: [],
};

const find = (checks: Check[], name: string): Check => {
  const c = checks.find((x) => x.name === name);
  if (!c) throw new Error(`no check named ${name}`);
  return c;
};

describe("buildReport", () => {
  test("all-clear inputs produce no fail/warn", () => {
    const checks = buildReport(OK);
    expect(checks.every((c) => c.status === "ok")).toBe(true);
    expect(worstStatus(checks)).toBe("ok");
  });

  test("a bash grant is not an orphan — the guard has no upstream by design", () => {
    const checks = buildReport({ ...OK, grantTools: ["github", "bash"] });
    expect(find(checks, "grants").status).toBe("ok");
    expect(worstStatus(checks)).toBe("ok");
  });

  test("config error fails the config check and the overall status", () => {
    const checks = buildReport({ ...OK, configError: "invalid grenz.yaml at `agents`: required" });
    expect(find(checks, "config").status).toBe("fail");
    expect(find(checks, "config").detail).toContain("invalid grenz.yaml");
    expect(worstStatus(checks)).toBe("fail");
  });

  test("vault error fails vault and collapses credentials to one fail", () => {
    const checks = buildReport({ ...OK, vaultError: "could not decrypt vault", credentialPresent: {} });
    expect(find(checks, "vault").status).toBe("fail");
    expect(find(checks, "credentials").status).toBe("fail");
    expect(find(checks, "credentials").detail).toContain("vault must decrypt first");
    expect(worstStatus(checks)).toBe("fail");
  });

  test("a missing upstream credential fails, naming the key but never a value", () => {
    const checks = buildReport({ ...OK, credentialPresent: { gh_token: false } });
    const cred = checks.find((c) => c.name === "credentials" && c.status === "fail");
    expect(cred).toBeDefined();
    expect(cred!.detail).toContain("gh_token");
    expect(cred!.detail).toContain("github");
    expect(worstStatus(checks)).toBe("fail");
  });

  test("an orphan grant tool warns (exit stays 0)", () => {
    const checks = buildReport({ ...OK, grantTools: ["github", "ghost"] });
    const orphan = checks.find((c) => c.name === "grants" && c.status === "warn");
    expect(orphan).toBeDefined();
    expect(orphan!.detail).toContain("ghost");
    expect(worstStatus(checks)).toBe("warn");
  });

  test("a real upstream with no policy grant warns (the wrap → silent-403 trap)", () => {
    const checks = buildReport({
      ...OK,
      upstreams: {
        github: { type: "github", decoy: false, credential: "gh_token" },
        linear: { type: "mcp", decoy: false, credential: "lin_token" },
      },
      credentialPresent: { gh_token: true, lin_token: true },
      grantTools: ["github"], // linear has no grant
    });
    const cov = checks.find((c) => c.name === "coverage" && c.status === "warn");
    expect(cov).toBeDefined();
    expect(cov!.detail).toContain("linear");
    expect(cov!.detail).toMatch(/denied|no policy grant/i);
    expect(worstStatus(checks)).toBe("warn");
  });

  test("a decoy upstream with no grant is NOT flagged (decoys are ungranted by design)", () => {
    const checks = buildReport({
      ...OK,
      upstreams: {
        github: { type: "github", decoy: false, credential: "gh_token" },
        honeypot: { type: "mcp", decoy: true, credential: null },
      },
      grantTools: ["github"],
    });
    expect(checks.find((c) => c.name === "coverage" && c.detail.includes("honeypot"))).toBeUndefined();
  });

  test("every real upstream granted → a single ok coverage check", () => {
    const checks = buildReport(OK); // github upstream + github grant
    const cov = checks.find((c) => c.name === "coverage");
    expect(cov).toBeDefined();
    expect(cov!.status).toBe("ok");
  });

  test("missing admin token and busy port are warnings", () => {
    const checks = buildReport({ ...OK, adminTokenPresent: false, portInUse: true });
    expect(find(checks, "admin token").status).toBe("warn");
    expect(find(checks, "port").status).toBe("warn");
    expect(worstStatus(checks)).toBe("warn");
  });

  test("policy compile reports the grant count", () => {
    const checks = buildReport({ ...OK, grantCount: 5 });
    expect(find(checks, "policy").detail).toContain("5");
  });

  test("an agent with a past expiry fails the agent-token check, naming the id", () => {
    const now = 100 * 86_400_000;
    const checks = buildReport({ ...OK, now, agents: [{ id: "claude-code", expiresAtMs: now - 86_400_000 }] });
    const at = find(checks, "agent token");
    expect(at.status).toBe("fail");
    expect(at.detail).toContain("claude-code");
    expect(at.detail).toContain("rotate");
    expect(worstStatus(checks)).toBe("fail");
  });

  test("an agent expiring within the week warns (exit stays 0)", () => {
    const now = 100 * 86_400_000;
    const checks = buildReport({ ...OK, now, agents: [{ id: "claude-code", expiresAtMs: now + 3 * 86_400_000 }] });
    const at = find(checks, "agent token");
    expect(at.status).toBe("warn");
    expect(at.detail).toContain("claude-code");
    expect(worstStatus(checks)).toBe("warn");
  });

  test("an agent with no expiry adds no agent-token check", () => {
    const checks = buildReport({ ...OK, agents: [{ id: "claude-code", expiresAtMs: null }] });
    expect(checks.some((c) => c.name === "agent token")).toBe(false);
  });

  test("TCP-only (socket null) adds no socket check", () => {
    expect(buildReport(OK).some((c) => c.name === "socket")).toBe(false);
  });

  test("a healthy socket is OK and names the path", () => {
    const checks = buildReport({
      ...OK,
      socket: { path: "/h/.grenz/run/agent.sock", pathError: null, dirMode: 0o700, stale: false },
    });
    const s = find(checks, "socket");
    expect(s.status).toBe("ok");
    expect(s.detail).toContain("/h/.grenz/run/agent.sock");
    expect(worstStatus(checks)).toBe("ok");
  });

  test("an unusable socket path fails, surfacing the resolver's message", () => {
    const checks = buildReport({
      ...OK,
      socket: { path: "x", pathError: "listen.socket path is too long (120 bytes, max 103)", dirMode: null, stale: false },
    });
    expect(find(checks, "socket").status).toBe("fail");
    expect(find(checks, "socket").detail).toMatch(/too long/);
    expect(worstStatus(checks)).toBe("fail");
  });

  test("a loose parent directory fails — it is the actual enforcement mechanism", () => {
    const checks = buildReport({
      ...OK,
      socket: { path: "/h/run/a.sock", pathError: null, dirMode: 0o755, stale: false },
    });
    expect(find(checks, "socket").status).toBe("fail");
    expect(find(checks, "socket").detail).toMatch(/group\/other/);
    expect(worstStatus(checks)).toBe("fail");
  });

  test("a stale socket warns (startup removes it) rather than failing", () => {
    const checks = buildReport({
      ...OK,
      socket: { path: "/h/run/a.sock", pathError: null, dirMode: 0o700, stale: true },
    });
    expect(find(checks, "socket").status).toBe("warn");
    expect(worstStatus(checks)).toBe("warn");
  });

  test("integrations line reflects the three booleans", () => {
    const checks = buildReport(OK);
    const detail = find(checks, "integrations").detail;
    expect(detail).toContain("slack off");
    expect(detail).toContain("llm on");
    expect(detail).toContain("telemetry off");
  });
});

describe("worstStatus", () => {
  test("fail beats warn beats ok", () => {
    expect(worstStatus([{ name: "a", status: "ok", detail: "" }])).toBe("ok");
    expect(worstStatus([{ name: "a", status: "ok", detail: "" }, { name: "b", status: "warn", detail: "" }])).toBe("warn");
    expect(worstStatus([{ name: "a", status: "warn", detail: "" }, { name: "b", status: "fail", detail: "" }])).toBe("fail");
  });

  test("empty list is ok", () => {
    expect(worstStatus([])).toBe("ok");
  });
});

describe("plane blocks", () => {
  const withTelemetry = (present: boolean): DoctorInputs => ({
    ...OK,
    integrations: { ...OK.integrations, telemetryEnabled: true },
    planeKeys: [{ block: "telemetry", key: "cloud_org_token", present }],
  });

  test("a configured block with its key present is ok", () => {
    const checks = buildReport(withTelemetry(true));
    expect(find(checks, "plane").status).toBe("ok");
    expect(find(checks, "plane").detail).toContain("cloud_org_token");
    expect(worstStatus(checks)).toBe("ok");
  });

  test("telemetry enabled with no key in the vault fails, and says what that costs", () => {
    // This is the whole reason the check exists: the proxy prints one line to
    // stderr and runs on with telemetry off, so preflight has to catch it.
    const checks = buildReport(withTelemetry(false));
    expect(find(checks, "plane").status).toBe("fail");
    expect(find(checks, "plane").detail).toContain("missing");
    expect(find(checks, "plane").detail).toContain("decision counts stay empty");
    expect(worstStatus(checks)).toBe("fail");
  });

  test("integrations reports what will happen, not what was asked for", () => {
    expect(find(buildReport(withTelemetry(true)), "integrations").detail).toContain("telemetry on");
    expect(find(buildReport(withTelemetry(false)), "integrations").detail).toContain("telemetry off");
  });

  test("a missing policy_source key says the plane's policy will not apply", () => {
    const checks = buildReport({
      ...OK,
      planeKeys: [{ block: "policy_source", key: "cloud_org_token", present: false }],
    });
    expect(find(checks, "plane").status).toBe("fail");
    expect(find(checks, "plane").detail).toContain("local policy.yaml");
  });

  test("a missing relay key says approvals expire into a refusal", () => {
    const checks = buildReport({
      ...OK,
      planeKeys: [{ block: "relay", key: "relay_token", present: false }],
    });
    expect(find(checks, "plane").detail).toContain("expire into a refusal");
  });

  test("every configured block is reported, not just the first broken one", () => {
    const checks = buildReport({
      ...OK,
      planeKeys: [
        { block: "policy_source", key: "cloud_org_token", present: false },
        { block: "telemetry", key: "cloud_org_token", present: false },
      ],
    });
    expect(checks.filter((c) => c.name === "plane")).toHaveLength(2);
  });

  test("no configured blocks means no plane check at all", () => {
    expect(buildReport(OK).some((c) => c.name === "plane")).toBe(false);
  });

  test("an undecryptable vault collapses the plane checks to one fail", () => {
    const checks = buildReport({ ...OK, vaultError: "could not decrypt vault", ...{ credentialPresent: {} },
      planeKeys: [{ block: "telemetry", key: "cloud_org_token", present: false }] });
    expect(checks.filter((c) => c.name === "plane")).toHaveLength(1);
    expect(find(checks, "plane").detail).toContain("vault must decrypt first");
  });
});
