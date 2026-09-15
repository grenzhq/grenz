import { test, expect, describe, afterEach } from "bun:test";
import { HashicorpVaultCredentialStore } from "../src/vault/hashicorp-vault.ts";
import { VaultError } from "../src/vault/store.ts";

let server: ReturnType<typeof Bun.serve> | null = null;
afterEach(() => {
  server?.stop(true);
  server = null;
});

function store(over: Partial<{ field: string; cacheTtlMs: number; address: string }> = {}) {
  return new HashicorpVaultCredentialStore({
    address: over.address ?? `http://127.0.0.1:${server!.port}`,
    mount: "secret",
    pathPrefix: "grenz/",
    field: over.field ?? "value",
    token: "hvs.testtoken",
    cacheTtlMs: over.cacheTtlMs ?? 60_000,
  });
}

describe("HashicorpVaultCredentialStore", () => {
  test("get reads the field from a KV v2 body", async () => {
    server = Bun.serve({
      port: 0,
      fetch: (req) => {
        const u = new URL(req.url);
        expect(req.headers.get("x-vault-token")).toBe("hvs.testtoken");
        expect(u.pathname).toBe("/v1/secret/data/grenz/github_token");
        return Response.json({ data: { data: { value: "s3cret" } } });
      },
    });
    expect(await store().get("github_token")).toBe("s3cret");
  });

  test("a custom field is read", async () => {
    server = Bun.serve({ port: 0, fetch: () => Response.json({ data: { data: { pat: "abc" } } }) });
    expect(await store({ field: "pat" }).get("k")).toBe("abc");
  });

  test("404 -> undefined (credential_missing upstream)", async () => {
    server = Bun.serve({ port: 0, fetch: () => new Response("{}", { status: 404 }) });
    expect(await store().get("nope")).toBeUndefined();
  });

  test("200 with data.data:null (soft-deleted) -> undefined", async () => {
    server = Bun.serve({ port: 0, fetch: () => Response.json({ data: { data: null, metadata: {} } }) });
    expect(await store().get("k")).toBeUndefined();
  });

  test("403 -> VaultError(backend_error)", async () => {
    server = Bun.serve({ port: 0, fetch: () => new Response("denied", { status: 403 }) });
    await expect(store().get("k")).rejects.toMatchObject({ name: "VaultError", code: "backend_error" });
  });

  test("malformed body -> fixed-string VaultError(corrupt), and NO secret bytes in the error", async () => {
    server = Bun.serve({
      port: 0,
      fetch: () => Response.json({ WRONG: { data: { value: "LEAKME-secret" } } }),
    });
    try {
      await store().get("k");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultError);
      expect((err as VaultError).message).not.toContain("LEAKME");
      expect((err as VaultError).message).toBe("unexpected response shape from credential backend");
    }
  });

  test("keys() LISTs metadata names", async () => {
    server = Bun.serve({
      port: 0,
      fetch: (req) => {
        const u = new URL(req.url);
        expect(u.pathname).toBe("/v1/secret/metadata/grenz/");
        expect(u.searchParams.get("list")).toBe("true");
        return Response.json({ data: { keys: ["github_token", "linear_token"] } });
      },
    });
    expect(await store().keys()).toEqual(["github_token", "linear_token"]);
  });

  test("a cross-origin 307 is NOT followed (token stays on-origin)", async () => {
    const other = Bun.serve({
      port: 0,
      fetch: () => Response.json({ data: { data: { value: "leaked-via-redirect" } } }),
    });
    server = Bun.serve({
      port: 0,
      fetch: () =>
        new Response(null, {
          status: 307,
          headers: { location: `http://127.0.0.1:${other.port}/v1/secret/data/grenz/k` },
        }),
    });
    await expect(store().get("k")).rejects.toBeInstanceOf(VaultError);
    other.stop(true);
  });

  test("concurrent gets for the same key make ONE upstream request (singleflight)", async () => {
    let hits = 0;
    server = Bun.serve({
      port: 0,
      fetch: async () => {
        hits++;
        await Bun.sleep(20);
        return Response.json({ data: { data: { value: "s" } } });
      },
    });
    const s = store();
    const [a, b, c] = await Promise.all([s.get("k"), s.get("k"), s.get("k")]);
    expect([a, b, c]).toEqual(["s", "s", "s"]);
    expect(hits).toBe(1);
  });

  test("a cached value is reused within TTL, refetched after it expires", async () => {
    let hits = 0;
    server = Bun.serve({
      port: 0,
      fetch: () => {
        hits++;
        return Response.json({ data: { data: { value: "s" } } });
      },
    });
    const s = store({ cacheTtlMs: 30 });
    await s.get("k");
    await s.get("k");
    expect(hits).toBe(1); // second within TTL
    await Bun.sleep(45);
    await s.get("k");
    expect(hits).toBe(2); // after TTL
  });

  test("a miss is NOT cached (a just-fixed key recovers)", async () => {
    let phase = 0;
    server = Bun.serve({
      port: 0,
      fetch: () =>
        phase++ === 0
          ? new Response("{}", { status: 404 })
          : Response.json({ data: { data: { value: "now-here" } } }),
    });
    const s = store();
    expect(await s.get("k")).toBeUndefined(); // 404
    expect(await s.get("k")).toBe("now-here"); // refetched, not cached-miss
  });
});
