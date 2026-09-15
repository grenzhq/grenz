import { test, expect, describe, afterEach } from "bun:test";
import { fetchRevocationSet } from "../src/revocation/source.ts";
import { makeKey, signRevSet } from "./support/revocation-set.ts";

let server: ReturnType<typeof Bun.serve> | null = null;
afterEach(() => {
  server?.stop(true);
  server = null;
});

describe("fetchRevocationSet", () => {
  test("valid set -> ok with sorted members", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["z", "a"], 3, null);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchRevocationSet(`http://127.0.0.1:${server.port}/r`, "tok", [publicKeyB64], 0);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.revokedAgents).toEqual(["a", "z"]);
  });

  test("bad signature -> error", async () => {
    const { privJwkKey } = await makeKey();
    const other = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["a"], 3, null);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchRevocationSet(`http://127.0.0.1:${server.port}/r`, "t", [other.publicKeyB64], 0);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("signature invalid");
  });

  test("stale version -> error", async () => {
    const { privJwkKey, publicKeyB64 } = await makeKey();
    const bundle = await signRevSet(privJwkKey, ["a"], 2, null);
    server = Bun.serve({ port: 0, fetch: () => new Response(bundle) });
    const r = await fetchRevocationSet(`http://127.0.0.1:${server.port}/r`, "t", [publicKeyB64], 5);
    expect(r).toEqual({ ok: false, error: expect.stringContaining("stale") });
  });

  test("non-200 -> error", async () => {
    const { publicKeyB64 } = await makeKey();
    server = Bun.serve({ port: 0, fetch: () => new Response("no", { status: 503 }) });
    const r = await fetchRevocationSet(`http://127.0.0.1:${server.port}/r`, "t", [publicKeyB64], 0);
    expect(r).toEqual({ ok: false, error: expect.stringContaining("503") });
  });

  test("unreachable -> error", async () => {
    const { publicKeyB64 } = await makeKey();
    const r = await fetchRevocationSet("http://127.0.0.1:1/r", "t", [publicKeyB64], 0);
    expect(r.ok).toBe(false);
  });
});
