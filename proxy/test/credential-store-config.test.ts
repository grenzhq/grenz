import { test, expect, describe } from "bun:test";
import { configSchema } from "../src/config/schema.ts";

const base = {
  listen: { host: "127.0.0.1", port: 8787 },
  upstreams: {},
  agents: [{ id: "a", token_hash: "a".repeat(64) }],
};

describe("credential_store config", () => {
  test("absent -> age-file default", () => {
    const c = configSchema.parse(base);
    expect(c.credential_store).toEqual({ type: "age-file" });
  });

  test("hashicorp-vault arm fills defaults", () => {
    const c = configSchema.parse({
      ...base,
      credential_store: { type: "hashicorp-vault", address: "https://vault.example.com" },
    });
    expect(c.credential_store).toMatchObject({
      type: "hashicorp-vault",
      address: "https://vault.example.com",
      mount: "secret",
      path_prefix: "grenz/",
      field: "value",
      token_key: "hashivault_token",
      cache_ttl_seconds: 60,
    });
  });

  test("hashicorp-vault without an address fails to parse", () => {
    expect(() =>
      configSchema.parse({ ...base, credential_store: { type: "hashicorp-vault" } }),
    ).toThrow();
  });

  test("age-file with a stray address fails to parse (strict)", () => {
    expect(() =>
      configSchema.parse({ ...base, credential_store: { type: "age-file", address: "x" } }),
    ).toThrow();
  });
});
