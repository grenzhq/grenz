import { test, expect, describe } from "bun:test";
import { AgentStore } from "../src/agents/store.ts";
import type { AgentConfig } from "../src/config/schema.ts";

function agent(id: string, hashChar: string): AgentConfig {
  return { id, token_hash: hashChar.repeat(64), decoy: false, expiresAtMs: null } as AgentConfig;
}

describe("AgentStore", () => {
  test("current reflects the initial agents", () => {
    const store = new AgentStore([agent("claude-code", "a")]);
    expect(store.current.map((a) => a.id)).toEqual(["claude-code"]);
  });

  test("is decoupled from the initial array (a later push to it is not seen)", () => {
    const initial = [agent("claude-code", "a")];
    const store = new AgentStore(initial);
    (initial as AgentConfig[]).push(agent("sneaky", "f"));
    expect(store.current.map((a) => a.id)).toEqual(["claude-code"]);
  });

  test("add appends and is immediately visible in current", () => {
    const store = new AgentStore([agent("claude-code", "a")]);
    const r = store.add(agent("ci-bot", "b"));
    expect(r.ok).toBe(true);
    expect(store.current.map((a) => a.id)).toEqual(["claude-code", "ci-bot"]);
    expect(store.has("ci-bot")).toBe(true);
  });

  test("add rejects a duplicate id (fail closed) and does not mutate", () => {
    const store = new AgentStore([agent("claude-code", "a")]);
    const r = store.add(agent("claude-code", "b"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("already exists");
    expect(store.current).toHaveLength(1);
  });
});
