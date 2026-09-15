import { test, expect, describe } from "bun:test";
import { resolveUpstreamUrl } from "../src/proxy/egress.ts";

describe("resolveUpstreamUrl", () => {
  test("a normal rooted path stays on origin", () => {
    const r = resolveUpstreamUrl("https://api.github.com", "/repos/o/r", "");
    expect(r).toEqual({ ok: true, url: "https://api.github.com/repos/o/r" });
  });

  test("query string is preserved", () => {
    const r = resolveUpstreamUrl("https://api.github.com", "/repos", "a=1&b=2");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.url).toBe("https://api.github.com/repos?a=1&b=2");
  });

  test("a base_url path prefix is preserved (not dropped by a WHATWG resolver)", () => {
    const r = resolveUpstreamUrl("https://ghe.corp/api/v3", "/repos/o/r", "");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.url).toBe("https://ghe.corp/api/v3/repos/o/r");
  });

  test("a trailing slash on base_url is normalized", () => {
    const r = resolveUpstreamUrl("https://api.github.com/", "/repos", "");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.url).toBe("https://api.github.com/repos");
  });

  test("a dot-segment deep path stays on origin (no false positive)", () => {
    const r = resolveUpstreamUrl("https://api.github.com", "/a/../b", "");
    expect(r.ok).toBe(true);
  });

  test("a protocol-relative authority path is blocked", () => {
    expect(resolveUpstreamUrl("https://api.github.com", "//evil.com/x", "")).toEqual({ ok: false });
  });

  test("a non-rooted path is blocked", () => {
    expect(resolveUpstreamUrl("https://api.github.com", "evil", "")).toEqual({ ok: false });
  });

  test("an empty path is blocked (not a rooted pathname)", () => {
    expect(resolveUpstreamUrl("https://api.github.com", "", "")).toEqual({ ok: false });
  });

  test("an unparseable base_url is blocked (fail closed)", () => {
    expect(resolveUpstreamUrl("not a url", "/x", "")).toEqual({ ok: false });
  });
});
