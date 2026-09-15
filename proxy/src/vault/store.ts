/**
 * The credential vault interface.
 *
 * Real credentials exist ONLY inside the proxy, retrieved through this
 * interface at the moment of forwarding and never before. Designing the vault
 * behind `CredentialStore` lets env / 1Password / HashiCorp Vault backends slot
 * in later without touching call sites.
 *
 * CRITICAL: `VaultError` messages and codes must never embed a credential
 * value. Callers surface these to logs and HTTP responses.
 */

export type VaultErrorCode =
  | "no_identity" // the age identity file is missing/unreadable
  | "decrypt_failed" // wrong identity, or the vault file is not valid age
  | "corrupt" // decrypted payload is not the expected shape
  | "io_error" // filesystem failure
  | "backend_error"; // a remote credential backend (Vault) returned an error / was unreachable

export class VaultError extends Error {
  constructor(
    public readonly code: VaultErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "VaultError";
  }
}

/** Read-only credential access, used on the request hot path. */
export interface CredentialStore {
  /** Resolve a credential by vault key, or `undefined` if the key is absent. */
  get(key: string): Promise<string | undefined>;
  /** List the credential keys (names only — NEVER values). */
  keys(): Promise<string[]>;
}

/** Write access, used by `grenz vault set`. */
export interface WritableCredentialStore extends CredentialStore {
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}
