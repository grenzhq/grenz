import { test, expect, describe } from "bun:test";
import { headerSafe } from "../src/util/header.ts";

describe("headerSafe", () => {
  test("plain ASCII is unchanged", () => {
    expect(headerSafe("destructive - never allowed")).toBe("destructive - never allowed");
  });

  test("an em-dash (the real dogfood bug) folds to a hyphen", () => {
    expect(headerSafe("destructive — never allowed")).toBe("destructive - never allowed");
  });

  test("curly quotes and ellipsis normalise to ASCII", () => {
    expect(headerSafe("don’t “do” this…")).toBe(`don't "do" this...`);
  });

  test("emoji and other non-ASCII become ? (an astral emoji is a surrogate pair)", () => {
    expect(headerSafe("blocked 🚨 café")).toBe("blocked ?? caf?");
  });

  test("the result is always a valid HTTP header value (constructor never throws)", () => {
    for (const s of ["— — —", "🔥🔥", "naïve résumé", "a\tb", " line"]) {
      const safe = headerSafe(s);
      expect(() => new Response("x", { headers: { "x-grenz-hint": safe } })).not.toThrow();
    }
  });
});
