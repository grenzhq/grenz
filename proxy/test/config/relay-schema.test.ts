import { test, expect } from "bun:test";
import { configSchema, relaySchema } from "../../src/config/schema.ts";

const baseAgent = { id: "a1", token_hash: "a".repeat(64) };

test("relaySchema requires a url and defaults poll window to 25s", () => {
  const parsed = relaySchema.parse({ url: "https://relay.grenz.dev" });
  expect(parsed.poll_window_seconds).toBe(25);
});

test("relaySchema rejects a non-url", () => {
  expect(() => relaySchema.parse({ url: "not-a-url" })).toThrow();
});

test("relaySchema accepts a custom poll window", () => {
  expect(relaySchema.parse({ url: "https://r.dev", poll_window_seconds: 10 }).poll_window_seconds).toBe(10);
});

test("configSchema accepts an optional relay block", () => {
  const cfg = configSchema.parse({
    agents: [baseAgent],
    credential_store: { type: "age-file" },
    relay: { url: "https://relay.grenz.dev" },
  });
  expect(cfg.relay?.url).toBe("https://relay.grenz.dev");
  expect(cfg.relay?.poll_window_seconds).toBe(25);
});

test("configSchema omits relay when not provided", () => {
  const cfg = configSchema.parse({ agents: [baseAgent], credential_store: { type: "age-file" } });
  expect(cfg.relay).toBeUndefined();
});
