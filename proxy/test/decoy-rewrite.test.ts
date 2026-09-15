import { test, expect, describe } from "bun:test";
import { parse } from "yaml";
import {
  addDecoyAgent,
  addDecoyUpstream,
  removeDecoyAgent,
  removeDecoyUpstream,
} from "../src/config/rewrite.ts";

const BASE = `# my config
agents:
  - id: real
    token_hash: ${"a".repeat(64)}
upstreams:
  github:
    type: github
    base_url: https://api.github.com
    credential: github_token
`;

describe("decoy rewrite helpers", () => {
  test("addDecoyAgent appends a decoy agent, preserving the comment", () => {
    const r = addDecoyAgent(BASE, "trap", "b".repeat(64));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.yaml).toContain("# my config");
      const cfg = parse(r.yaml) as { agents: { id: string; token_hash: string; decoy?: boolean }[] };
      const trap = cfg.agents.find((a) => a.id === "trap");
      expect(trap).toMatchObject({ id: "trap", token_hash: "b".repeat(64), decoy: true });
    }
  });

  test("addDecoyAgent refuses a duplicate id", () => {
    const r = addDecoyAgent(BASE, "real", "c".repeat(64));
    expect(r.ok).toBe(false);
  });

  test("addDecoyUpstream adds a decoy upstream", () => {
    const r = addDecoyUpstream(BASE, "honeypot");
    expect(r.ok).toBe(true);
    if (r.ok) {
      const cfg = parse(r.yaml) as { upstreams: Record<string, { decoy?: boolean; type: string }> };
      expect(cfg.upstreams.honeypot).toEqual({ decoy: true, type: "mcp" });
    }
  });

  test("addDecoyUpstream refuses a name collision", () => {
    expect(addDecoyUpstream(BASE, "github").ok).toBe(false);
  });

  test("removeDecoyAgent removes only a decoy, refuses a real agent", () => {
    const withTrap = addDecoyAgent(BASE, "trap", "b".repeat(64));
    if (!withTrap.ok) throw new Error("setup");
    expect(removeDecoyAgent(withTrap.yaml, "trap").ok).toBe(true);
    const refuse = removeDecoyAgent(BASE, "real");
    expect(refuse.ok).toBe(false); // real is not a decoy
  });

  test("removeDecoyUpstream removes only a decoy, refuses a real upstream", () => {
    const withHp = addDecoyUpstream(BASE, "honeypot");
    if (!withHp.ok) throw new Error("setup");
    expect(removeDecoyUpstream(withHp.yaml, "honeypot").ok).toBe(true);
    expect(removeDecoyUpstream(BASE, "github").ok).toBe(false); // github is real
  });
});
