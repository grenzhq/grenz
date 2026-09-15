import { test, expect, describe } from "bun:test";
import { addAgent } from "../src/config/rewrite.ts";
import { configSchema } from "../src/config/schema.ts";
import { parse } from "yaml";

const HASH_A = "a".repeat(64);
const NEW = "c".repeat(64);

const COMMENTED = `# grenz.yaml — non-secret runtime config.
listen:
  host: 127.0.0.1
  port: 8787

agents:
  - id: claude-code
    token_hash: ${HASH_A}   # the agent's token hash
`;

describe("addAgent (config rewrite)", () => {
  test("appends a new agent and preserves comments + other agents", () => {
    const r = addAgent(COMMENTED, "ci-bot", NEW);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.yaml).toContain("id: ci-bot");
    expect(r.yaml).toContain(`token_hash: ${NEW}`);
    expect(r.yaml).toContain("id: claude-code"); // existing agent intact
    expect(r.yaml).toContain(`token_hash: ${HASH_A}`);
    expect(r.yaml).toContain("# grenz.yaml — non-secret runtime config.");
    expect(r.yaml).toContain("port: 8787");
  });

  test("the appended agent is first-class — no decoy flag", () => {
    const r = addAgent(COMMENTED, "ci-bot", NEW);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const doc = parse(r.yaml) as { agents: Array<Record<string, unknown>> };
    const added = doc.agents.find((a) => a.id === "ci-bot")!;
    expect(added.decoy).toBeUndefined();
  });

  test("the rewritten yaml still parses under the strict config schema", () => {
    const r = addAgent(COMMENTED, "ci-bot", NEW);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const parsed = configSchema.safeParse(parse(r.yaml));
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.agents.map((a) => a.id).sort()).toEqual(["ci-bot", "claude-code"]);
    }
  });

  test("writes actions + targets lists and they round-trip through the strict schema", () => {
    const r = addAgent(COMMENTED, "reviewer-acme", NEW, {
      actions: ["repo:read", "pr:read"],
      targets: ["/repos/acme/*", "/repos/team/app"],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const parsed = configSchema.safeParse(parse(r.yaml));
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const added = parsed.data.agents.find((a) => a.id === "reviewer-acme")!;
    expect(added.actions).toEqual(["repo:read", "pr:read"]);
    expect(added.targets).toEqual(["/repos/acme/*", "/repos/team/app"]);
    expect(r.yaml).toContain("# grenz.yaml — non-secret runtime config."); // comments intact
  });

  test("one axis alone works (targets only, actions absent)", () => {
    const r = addAgent(COMMENTED, "reviewer-acme", NEW, { targets: ["/repos/acme/*"] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const parsed = configSchema.safeParse(parse(r.yaml));
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const added = parsed.data.agents.find((a) => a.id === "reviewer-acme")!;
    expect(added.actions).toBeUndefined();
    expect(added.targets).toEqual(["/repos/acme/*"]);
  });

  test("empty/absent scope leaves the agent unrestricted (no actions/targets keys)", () => {
    for (const s of [undefined, {}, { actions: [] as string[], targets: [] as string[] }]) {
      const r = addAgent(COMMENTED, "ci-bot", NEW, s);
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      const doc = parse(r.yaml) as { agents: Array<Record<string, unknown>> };
      const added = doc.agents.find((a) => a.id === "ci-bot")!;
      expect(added.targets).toBeUndefined();
      expect(added.actions).toBeUndefined();
    }
  });

  test("writes a policy profile name and it round-trips through the strict schema", () => {
    const withProfiles = `${COMMENTED}
policy_profiles:
  ci-merge: { file: profiles/ci.yaml }
`;
    const r = addAgent(withProfiles, "ci-bot", NEW, { policy: "ci-merge" });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.yaml).toContain("policy: ci-merge");
    const parsed = configSchema.safeParse(parse(r.yaml));
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const added = parsed.data.agents.find((a) => a.id === "ci-bot")!;
    expect(added.policy).toBe("ci-merge");
  });

  test("policy composes with scope (actions/targets) on the same agent", () => {
    const withProfiles = `${COMMENTED}
policy_profiles:
  ci-merge: { file: profiles/ci.yaml }
`;
    const r = addAgent(withProfiles, "ci-bot", NEW, {
      policy: "ci-merge",
      actions: ["pr:merge"],
      targets: ["/repos/acme/*"],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const doc = parse(r.yaml) as { agents: Array<Record<string, unknown>> };
    const added = doc.agents.find((a) => a.id === "ci-bot")!;
    expect(added.policy).toBe("ci-merge");
    expect(added.actions).toEqual(["pr:merge"]);
    expect(added.targets).toEqual(["/repos/acme/*"]);
  });

  test("absent policy writes no policy key (unchanged default behavior)", () => {
    const r = addAgent(COMMENTED, "ci-bot", NEW, { actions: ["pr:read"] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const doc = parse(r.yaml) as { agents: Array<Record<string, unknown>> };
    const added = doc.agents.find((a) => a.id === "ci-bot")!;
    expect(added.policy).toBeUndefined();
  });

  test("rejects a duplicate id (fail closed)", () => {
    const r = addAgent(COMMENTED, "claude-code", NEW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("already exists");
  });

  test("rejects a file with no agents list", () => {
    const r = addAgent("listen:\n  port: 8787\n", "ci-bot", NEW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("no agents list");
  });

  test("rejects malformed yaml", () => {
    const r = addAgent("agents: [ unterminated", "ci-bot", NEW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("invalid grenz.yaml");
  });
});
