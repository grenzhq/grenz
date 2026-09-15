/**
 * `AgeFileCredentialStore` — the v0 vault: an age-encrypted local file.
 *
 * On disk:
 *   identity   the age secret key (AGE-SECRET-KEY-...), file mode 0600
 *   vault.age  the credential map, encrypted to the identity's recipient
 *
 * The decrypted map is a `Record<string,string>` of vaultKey -> credential.
 * Credentials live in memory only after an explicit `get`/load and never leave
 * this module except as the return value of `get`. Errors never carry values.
 */
import * as age from "age-encryption";
import { z } from "zod";
import { chmod } from "node:fs/promises";
import { VaultError, type WritableCredentialStore } from "./store.ts";

const vaultShape = z.record(z.string(), z.string());

export interface AgeFilePaths {
  readonly identityPath: string;
  readonly vaultPath: string;
}

export class AgeFileCredentialStore implements WritableCredentialStore {
  private cache: Map<string, string> | null = null;
  private recipient: string | null = null;

  constructor(private readonly paths: AgeFilePaths) {}

  /** Generate a fresh age identity + its recipient (used by `grenz init`). */
  static async generateIdentity(): Promise<{ identity: string; recipient: string }> {
    const identity = await age.generateIdentity();
    const recipient = await age.identityToRecipient(identity);
    return { identity, recipient };
  }

  private async readIdentity(): Promise<string> {
    const file = Bun.file(this.paths.identityPath);
    if (!(await file.exists())) {
      throw new VaultError("no_identity", `age identity not found at ${this.paths.identityPath}`);
    }
    try {
      const text = (await file.text()).trim();
      if (!text.startsWith("AGE-SECRET-KEY-")) {
        throw new VaultError("no_identity", "identity file is not a valid age secret key");
      }
      return text;
    } catch (err) {
      if (err instanceof VaultError) throw err;
      throw new VaultError("io_error", "could not read age identity file");
    }
  }

  private async load(): Promise<Map<string, string>> {
    if (this.cache) return this.cache;

    const identity = await this.readIdentity();
    this.recipient = await age.identityToRecipient(identity);

    const vaultFile = Bun.file(this.paths.vaultPath);
    if (!(await vaultFile.exists())) {
      // A fresh, never-written vault is an empty map, not an error.
      this.cache = new Map();
      return this.cache;
    }

    let plaintext: string;
    try {
      const ciphertext = new Uint8Array(await vaultFile.arrayBuffer());
      const decrypter = new age.Decrypter();
      decrypter.addIdentity(identity);
      plaintext = await decrypter.decrypt(ciphertext, "text");
    } catch {
      throw new VaultError("decrypt_failed", "could not decrypt vault (wrong identity or corrupt file)");
    }

    let json: unknown;
    try {
      json = JSON.parse(plaintext);
    } catch {
      throw new VaultError("corrupt", "decrypted vault is not valid JSON");
    }
    const parsed = vaultShape.safeParse(json);
    if (!parsed.success) {
      throw new VaultError("corrupt", "decrypted vault is not a string map");
    }

    this.cache = new Map(Object.entries(parsed.data));
    return this.cache;
  }

  private async persist(map: Map<string, string>): Promise<void> {
    if (!this.recipient) {
      // load() sets recipient; if we somehow got here, derive it now.
      const identity = await this.readIdentity();
      this.recipient = await age.identityToRecipient(identity);
    }
    const obj: Record<string, string> = {};
    for (const [k, v] of map) obj[k] = v;

    const encrypter = new age.Encrypter();
    encrypter.addRecipient(this.recipient);
    const ciphertext = await encrypter.encrypt(new TextEncoder().encode(JSON.stringify(obj)));

    try {
      await Bun.write(this.paths.vaultPath, ciphertext);
      await chmod(this.paths.vaultPath, 0o600);
    } catch {
      throw new VaultError("io_error", "could not write vault file");
    }
  }

  /** Write an empty encrypted vault if none exists yet. Never clobbers. */
  async createEmpty(): Promise<void> {
    if (await Bun.file(this.paths.vaultPath).exists()) return;
    this.cache = new Map();
    await this.persist(this.cache);
  }

  async get(key: string): Promise<string | undefined> {
    const map = await this.load();
    return map.get(key);
  }

  async keys(): Promise<string[]> {
    const map = await this.load();
    return [...map.keys()].sort();
  }

  async set(key: string, value: string): Promise<void> {
    const map = await this.load();
    map.set(key, value);
    await this.persist(map);
  }

  async remove(key: string): Promise<void> {
    const map = await this.load();
    map.delete(key);
    await this.persist(map);
  }
}
