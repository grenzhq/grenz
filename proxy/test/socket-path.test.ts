import { test, expect, describe } from "bun:test";
import { listenSchema } from "../src/config/schema.ts";
import { resolveSocketPath, MAX_SOCKET_PATH, SUN_PATH_MAX } from "../src/config/socket-path.ts";

describe("listen.socket schema", () => {
  test("absent → undefined (TCP-only, unchanged)", () => {
    expect(listenSchema.parse({}).socket).toBeUndefined();
  });
  test("a plain relative path parses", () => {
    expect(listenSchema.parse({ socket: "run/agent.sock" }).socket).toBe("run/agent.sock");
  });
  test("a NUL byte is rejected (Linux abstract-namespace bypass)", () => {
    expect(() => listenSchema.parse({ socket: "\0grenz" })).toThrow();
    expect(() => listenSchema.parse({ socket: "run/a\0b.sock" })).toThrow();
  });
  test("empty is rejected", () => {
    expect(() => listenSchema.parse({ socket: "" })).toThrow();
  });
  test("host/port still coexist with socket (admin plane stays TCP)", () => {
    const l = listenSchema.parse({ socket: "run/a.sock", host: "127.0.0.1", port: 9000 });
    expect(l).toMatchObject({ socket: "run/a.sock", host: "127.0.0.1", port: 9000 });
  });
});

describe("resolveSocketPath", () => {
  test("resolves a relative path against the home", () => {
    expect(resolveSocketPath("run/agent.sock", "/home/u/.grenz")).toEqual({
      ok: true,
      path: "/home/u/.grenz/run/agent.sock",
    });
  });
  test("keeps an already-absolute path", () => {
    expect(resolveSocketPath("/tmp/a.sock", "/home/u/.grenz")).toEqual({ ok: true, path: "/tmp/a.sock" });
  });
  test("rejects a resolved path over the sun_path bound", () => {
    const r = resolveSocketPath("x".repeat(MAX_SOCKET_PATH + 10) + ".sock", "/home/u/.grenz");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/too long/i);
  });
  test("rejects a NUL that reached the resolver anyway (defense in depth)", () => {
    expect(resolveSocketPath("a\0b.sock", "/home/u/.grenz").ok).toBe(false);
  });
  test("measures BYTES, not characters (multibyte paths)", () => {
    // "é" is 2 bytes: fewer characters than the bound, but more bytes.
    const r = resolveSocketPath("é".repeat(MAX_SOCKET_PATH - 20) + ".sock", "/h");
    expect(r.ok).toBe(false);
  });
  test("a path exactly at the bound is accepted", () => {
    const home = "/h";
    const name = "y".repeat(MAX_SOCKET_PATH - home.length - 1); // "/h/" + name
    const r = resolveSocketPath(name, home);
    expect(r.ok).toBe(true);
    if (r.ok) expect(Buffer.byteLength(r.path, "utf8")).toBe(MAX_SOCKET_PATH);
  });

  // The path that actually reaches bind() is the staging name, not this one.
  // A configured path accepted here must leave room for it, or socket mode
  // would pass validation and then fail at startup with ENAMETOOLONG.
  test("an accepted path still fits once the staging suffix is appended", () => {
    const home = "/h";
    const name = "y".repeat(MAX_SOCKET_PATH - home.length - 1);
    const r = resolveSocketPath(name, home);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const worstCaseStaging = `${r.path}.${"9".repeat(7)}.tmp`;
    expect(Buffer.byteLength(worstCaseStaging, "utf8")).toBeLessThanOrEqual(SUN_PATH_MAX);
  });
});
