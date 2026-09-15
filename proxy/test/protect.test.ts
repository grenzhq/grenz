import { test, expect, describe, beforeEach } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyProtect, PRESETS } from "../src/cli/protect.ts";
import { grenzPaths } from "../src/config/paths.ts";
import { compilePolicyYaml } from "../src/policy/compile.ts";
import { AgeFileCredentialStore } from "../src/vault/age-file.ts";

const SECRET = "ghp_dummy_not_a_real_secret_value_1234567890";
const GH = PRESETS.github!;

describe("grenz protect (applyProtect)", () => {
  let home: string;
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "grenz-protect-"));
  });

  test("scaffolds, vaults the token, writes classified safe-defaults, prints the outcome", async () => {
    const paths = grenzPaths(home);
    const outcome = await applyProtect({ paths, tool: "github", preset: GH, preference: "normal", secret: SECRET });

    // the generated policy gates the irreversible actions and compiles for real
    const policy = await Bun.file(paths.policy).text();
    for (const a of ["pr:merge", "repo:delete", "actions:write", "api:write"]) expect(policy).toContain(a);
    expect(compilePolicyYaml(policy).ok).toBe(true);

    // the token is in the vault, retrievable, exactly as given
    const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
    expect(await vault.get("github_token")).toBe(SECRET);

    // grenz.yaml routes the github upstream at the vault key
    const config = await Bun.file(paths.config).text();
    expect(config).toContain("type: github");
    expect(config).toContain("credential: github_token");

    // an admin token exists (console/admin API works day zero)
    expect(await Bun.file(paths.adminToken).exists()).toBe(true);

    // the outcome makes the falsifiable claim
    expect(outcome).toContain("no longer holds it");
    expect(outcome).toContain("pr:merge");
  });

  test("the real credential NEVER leaks — not in the outcome, policy, config, or (plaintext) vault", async () => {
    const paths = grenzPaths(home);
    const outcome = await applyProtect({ paths, tool: "github", preset: GH, preference: "normal", secret: SECRET });
    expect(outcome).not.toContain(SECRET);
    expect(await Bun.file(paths.policy).text()).not.toContain(SECRET);
    expect(await Bun.file(paths.config).text()).not.toContain(SECRET);
    expect(await Bun.file(paths.vault).text()).not.toContain(SECRET); // vault is age-encrypted
  });

  test("strict preference gates the sensitive edits too", async () => {
    const paths = grenzPaths(home);
    await applyProtect({ paths, tool: "github", preset: GH, preference: "strict", secret: SECRET });
    const policy = await Bun.file(paths.policy).text();
    const requireApprovalBlock = policy.split("require_approval:")[1] ?? "";
    expect(requireApprovalBlock).toContain("pr:comment"); // sensitive → approval in strict
  });
});
