/**
 * The admin token gates the loopback console/admin API (list requests, list and
 * decide approvals). It is a LOCAL secret — like the age identity — stored as a
 * 0600 file so the `grenz` CLI and the local console can read it without
 * decrypting the vault. It is not the agent's GRENZ_TOKEN and grants no
 * upstream access; it only operates the console.
 */
import { chmod } from "node:fs/promises";
import { generateToken } from "../util/token.ts";

/** Read the admin token, creating (0600) it if absent. Safe to call on upgrade. */
export async function ensureAdminToken(path: string): Promise<string> {
  const file = Bun.file(path);
  if (await file.exists()) {
    const text = (await file.text()).trim();
    if (text.length > 0) return text;
  }
  const token = generateToken("grenz-adm");
  await Bun.write(path, `${token}\n`);
  await chmod(path, 0o600);
  return token;
}

/** Read the admin token, or null if it does not exist yet. */
export async function readAdminToken(path: string): Promise<string | null> {
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  const text = (await file.text()).trim();
  return text.length > 0 ? text : null;
}
