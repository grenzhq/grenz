import { test, expect, describe } from "bun:test";
import { extractToken } from "../src/proxy/auth.ts";
import { constantTimeEqual, generateToken, hashToken } from "../src/util/token.ts";

describe("token utils", () => {
  test("generateToken is prefixed and unique", () => {
    const a = generateToken();
    const b = generateToken();
    expect(a.startsWith("grenz_")).toBe(true);
    expect(a).not.toBe(b);
  });

  test("hashToken is stable hex sha-256", async () => {
    const h1 = await hashToken("grenz_abc");
    const h2 = await hashToken("grenz_abc");
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  test("constantTimeEqual", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
  });
});

describe("extractToken", () => {
  test("from Authorization: Bearer", () => {
    const h = new Headers({ authorization: "Bearer grenz_xyz" });
    expect(extractToken(h)).toBe("grenz_xyz");
  });
  test("from X-Grenz-Token", () => {
    const h = new Headers({ "x-grenz-token": "grenz_xyz" });
    expect(extractToken(h)).toBe("grenz_xyz");
  });
  test("none present -> null", () => {
    expect(extractToken(new Headers())).toBeNull();
  });
  test("non-bearer authorization -> null", () => {
    const h = new Headers({ authorization: "Basic abc" });
    expect(extractToken(h)).toBeNull();
  });
});
