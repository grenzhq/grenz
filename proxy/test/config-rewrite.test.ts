import { test, expect, describe } from "bun:test";
import { setAgentTokenHash } from "../src/config/rewrite.ts";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const NEW = "c".repeat(64);

const COMMENTED = `# grenz.yaml — non-secret runtime config.
listen:
  host: 127.0.0.1
  port: 8787

agents:
  - id: claude-code
    token_hash: ${HASH_A}   # the agent's token hash
`;

const TWO_AGENTS = `agents:
  - id: alice
    token_hash: ${HASH_A}
  - id: bob
    token_hash: ${HASH_B}
`;

describe("setAgentTokenHash", () => {
  test("replaces the named agent's token_hash", () => {
    const r = setAgentTokenHash(COMMENTED, "claude-code", NEW);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.yaml).toContain(`token_hash: ${NEW}`);
      expect(r.yaml).not.toContain(HASH_A);
    }
  });

  test("preserves comments and other keys", () => {
    const r = setAgentTokenHash(COMMENTED, "claude-code", NEW);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.yaml).toContain("# grenz.yaml — non-secret runtime config.");
      expect(r.yaml).toContain("port: 8787");
      expect(r.yaml).toContain("the agent's token hash"); // inline comment survives
    }
  });

  test("with two agents, only the named one changes", () => {
    const r = setAgentTokenHash(TWO_AGENTS, "bob", NEW);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.yaml).toContain(`token_hash: ${HASH_A}`); // alice untouched
      expect(r.yaml).toContain(`token_hash: ${NEW}`); // bob rotated
      expect(r.yaml).not.toContain(HASH_B);
    }
  });

  test("unknown agent id is rejected", () => {
    const r = setAgentTokenHash(COMMENTED, "ghost", NEW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("ghost");
  });

  test("a document with no agents list is rejected", () => {
    const r = setAgentTokenHash("listen:\n  port: 8787\n", "claude-code", NEW);
    expect(r.ok).toBe(false);
  });

  test("malformed YAML is rejected", () => {
    const r = setAgentTokenHash("agents: : :\n  - broken", "claude-code", NEW);
    expect(r.ok).toBe(false);
  });
});
