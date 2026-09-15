import { test, expect, describe, afterEach } from "bun:test";
import { forward } from "../src/proxy/forward.ts";
import type { RealUpstreamConfig } from "../src/config/schema.ts";

let server: ReturnType<typeof Bun.serve> | null = null;
afterEach(() => {
  server?.stop(true);
  server = null;
});

const upstream = (port: number | undefined): RealUpstreamConfig => ({
  type: "github",
  base_url: `http://127.0.0.1:${port}`,
  credential: "github_token",
  inject: { header: "Authorization", scheme: "Bearer" },
  decoy: false,
});

async function bodyLen(res: Response): Promise<number> {
  return (await res.arrayBuffer()).byteLength;
}

describe("forward with responseLimit", () => {
  test("no limit -> full body, outcome ok", async () => {
    server = Bun.serve({ port: 0, fetch: () => new Response("x".repeat(1000)) });
    const r = await forward({
      upstream: upstream(server.port),
      credential: "tok",
      method: "GET",
      url: `http://127.0.0.1:${server.port}/`,
      requestHeaders: new Headers(),
      body: null,
    });
    expect(r.outcome).toBe("ok");
    if (r.outcome !== "too_large") expect(await bodyLen(r.response)).toBe(1000);
  });

  test("truncate: oversized body is capped", async () => {
    server = Bun.serve({ port: 0, fetch: () => new Response("x".repeat(1000)) });
    const r = await forward({
      upstream: upstream(server.port),
      credential: "tok",
      method: "GET",
      url: `http://127.0.0.1:${server.port}/`,
      requestHeaders: new Headers(),
      body: null,
      responseLimit: { maxBytes: 100, onExceed: "truncate" },
    });
    expect(r.outcome === "too_large").toBe(false);
    if (r.outcome !== "too_large") {
      expect(r.response.headers.get("x-grenz-response-limit")).toBe("100");
      expect(await bodyLen(r.response)).toBe(100);
    }
  });

  test("deny + declared content-length over cap -> too_large, no body", async () => {
    server = Bun.serve({ port: 0, fetch: () => new Response("x".repeat(1000)) }); // Bun sets content-length
    const r = await forward({
      upstream: upstream(server.port),
      credential: "tok",
      method: "GET",
      url: `http://127.0.0.1:${server.port}/`,
      requestHeaders: new Headers(),
      body: null,
      responseLimit: { maxBytes: 100, onExceed: "deny" },
    });
    expect(r.outcome).toBe("too_large");
    expect(r.status).toBe(200); // upstream status; server.ts maps the refusal to 413
  });

  test("deny + unknown length degrades to truncation", async () => {
    server = Bun.serve({
      port: 0,
      fetch: () =>
        new Response(
          new ReadableStream({
            start(c) {
              for (let i = 0; i < 50; i++) c.enqueue(new TextEncoder().encode("xxxxxxxxxx")); // 500 bytes
              c.close();
            },
          }),
        ),
    });
    const r = await forward({
      upstream: upstream(server.port),
      credential: "tok",
      method: "GET",
      url: `http://127.0.0.1:${server.port}/`,
      requestHeaders: new Headers(),
      body: null,
      responseLimit: { maxBytes: 100, onExceed: "deny" },
    });
    expect(r.outcome === "too_large").toBe(false);
    if (r.outcome !== "too_large") expect(await bodyLen(r.response)).toBe(100);
  });

  test("under-cap body is untouched but still carries the limit header", async () => {
    server = Bun.serve({ port: 0, fetch: () => new Response("x".repeat(50)) });
    const r = await forward({
      upstream: upstream(server.port),
      credential: "tok",
      method: "GET",
      url: `http://127.0.0.1:${server.port}/`,
      requestHeaders: new Headers(),
      body: null,
      responseLimit: { maxBytes: 100, onExceed: "truncate" },
    });
    expect(r.outcome).toBe("ok");
    if (r.outcome !== "too_large") {
      expect(r.response.headers.get("x-grenz-response-limit")).toBe("100");
      expect(r.response.headers.get("x-grenz-truncated")).toBeNull();
      expect(await bodyLen(r.response)).toBe(50);
    }
  });
});
