import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgeFileCredentialStore } from "../src/vault/age-file.ts";
import { VaultError } from "../src/vault/store.ts";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-vault-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function newStoreWithIdentity(): Promise<{ store: AgeFileCredentialStore; identityPath: string; vaultPath: string }> {
  const identityPath = join(dir, "identity");
  const vaultPath = join(dir, "vault.age");
  const { identity } = await AgeFileCredentialStore.generateIdentity();
  await Bun.write(identityPath, `${identity}\n`);
  return { store: new AgeFileCredentialStore({ identityPath, vaultPath }), identityPath, vaultPath };
}

describe("AgeFileCredentialStore", () => {
  test("set/get/keys roundtrip", async () => {
    const { store } = await newStoreWithIdentity();
    expect(await store.keys()).toEqual([]);
    await store.set("github_token", "ghp_secret_value");
    await store.set("linear_token", "lin_secret_value");
    expect(await store.get("github_token")).toBe("ghp_secret_value");
    expect(await store.get("linear_token")).toBe("lin_secret_value");
    expect(await store.keys()).toEqual(["github_token", "linear_token"]);
    expect(await store.get("missing")).toBeUndefined();
  });

  test("persists across store instances", async () => {
    const { store, identityPath, vaultPath } = await newStoreWithIdentity();
    await store.set("k", "v");
    const reopened = new AgeFileCredentialStore({ identityPath, vaultPath });
    expect(await reopened.get("k")).toBe("v");
  });

  test("remove deletes a key", async () => {
    const { store } = await newStoreWithIdentity();
    await store.set("k", "v");
    await store.remove("k");
    expect(await store.get("k")).toBeUndefined();
    expect(await store.keys()).toEqual([]);
  });

  test("vault file on disk is encrypted (no plaintext secret)", async () => {
    const { store, vaultPath } = await newStoreWithIdentity();
    const secret = "ghp_TOP_SECRET_should_never_be_plaintext";
    await store.set("github_token", secret);
    const bytes = new Uint8Array(await Bun.file(vaultPath).arrayBuffer());
    const asText = new TextDecoder().decode(bytes);
    expect(asText).not.toContain(secret);
    // sanity: it looks like an age file
    expect(asText.startsWith("age-encryption.org/v1")).toBe(true);
  });

  test("createEmpty writes an empty vault and never clobbers", async () => {
    const { store, vaultPath } = await newStoreWithIdentity();
    await store.set("k", "v");
    const before = await Bun.file(vaultPath).arrayBuffer();
    await store.createEmpty(); // must not overwrite existing vault
    const after = await Bun.file(vaultPath).arrayBuffer();
    expect(after.byteLength).toBe(before.byteLength);
    expect(await store.get("k")).toBe("v");
  });

  test("missing identity -> VaultError(no_identity)", async () => {
    const store = new AgeFileCredentialStore({
      identityPath: join(dir, "nope"),
      vaultPath: join(dir, "vault.age"),
    });
    await expect(store.keys()).rejects.toBeInstanceOf(VaultError);
    try {
      await store.keys();
    } catch (err) {
      expect((err as VaultError).code).toBe("no_identity");
    }
  });

  test("wrong identity -> VaultError(decrypt_failed), and no secret in message", async () => {
    const { store, vaultPath } = await newStoreWithIdentity();
    await store.set("github_token", "ghp_secret_value");

    // A different identity cannot decrypt the vault.
    const otherIdentityPath = join(dir, "other-identity");
    const { identity: other } = await AgeFileCredentialStore.generateIdentity();
    await Bun.write(otherIdentityPath, `${other}\n`);
    const wrong = new AgeFileCredentialStore({ identityPath: otherIdentityPath, vaultPath });

    try {
      await wrong.get("github_token");
      throw new Error("expected decrypt to fail");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultError);
      expect((err as VaultError).code).toBe("decrypt_failed");
      expect((err as VaultError).message).not.toContain("ghp_secret_value");
    }
  });
});
