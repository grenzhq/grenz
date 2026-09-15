import { test, expect, describe } from "bun:test";
import { upstreamSchema } from "../src/config/schema.ts";

describe("decoy upstream schema", () => {
  test("a minimal decoy upstream is accepted", () => {
    const u = upstreamSchema.parse({ decoy: true, type: "mcp" });
    expect(u).toEqual({ decoy: true, type: "mcp" });
  });

  test("a real upstream still parses and defaults decoy=false", () => {
    const u = upstreamSchema.parse({ type: "github", base_url: "https://api.github.com", credential: "gh" });
    expect(u).toMatchObject({ type: "github", decoy: false, credential: "gh" });
  });

  test("a decoy with a credential fails to load (unforwardable by construction)", () => {
    expect(() => upstreamSchema.parse({ decoy: true, type: "mcp", credential: "x" })).toThrow();
  });

  test("a decoy with a base_url fails to load", () => {
    expect(() => upstreamSchema.parse({ decoy: true, type: "mcp", base_url: "https://x.example" })).toThrow();
  });

  test("a decoy with an inject spec fails to load", () => {
    expect(() =>
      upstreamSchema.parse({ decoy: true, type: "mcp", inject: { header: "Authorization", scheme: "Bearer" } }),
    ).toThrow();
  });
});
