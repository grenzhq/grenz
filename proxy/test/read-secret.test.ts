import { test, expect, describe } from "bun:test";
import { cleanSecret } from "../src/cli/read-secret.ts";

describe("cleanSecret", () => {
  test("drops the newline pbpaste and echo add", () => {
    // The reason `tr -d '\n'` was in every instruction. A token stored with its
    // newline fails upstream auth in a way that reads as a bad token.
    expect(cleanSecret("grz_abc\n")).toBe("grz_abc");
    expect(cleanSecret("grz_abc\r\n")).toBe("grz_abc");
    expect(cleanSecret("grz_abc  \n\n")).toBe("grz_abc");
  });

  test("keeps leading characters — only the tail is a paste artifact", () => {
    expect(cleanSecret(" grz_abc")).toBe(" grz_abc");
  });

  test("an empty or whitespace-only value is empty, so callers can refuse it", () => {
    expect(cleanSecret("")).toBe("");
    expect(cleanSecret("\n")).toBe("");
    expect(cleanSecret("   ")).toBe("");
  });

  test("leaves an already-clean secret alone", () => {
    expect(cleanSecret("grz_abc")).toBe("grz_abc");
  });
});
