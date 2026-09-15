import { describe, expect, it } from "bun:test";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAll, ConfigError } from "./load.ts";

const HASH = "a".repeat(64);

function home(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "grenz-load-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

const DEFAULT_POLICY = `
agent: default
on_behalf_of: human
grants:
  - tool: github
    allow: ["pr:read"]
tripwires:
  - action: "danger:*"
`;

const CI_PROFILE = `
agent: ci
on_behalf_of: human
grants:
  - tool: github
    allow: ["pr:merge"]
`;

describe("loadAll profiles", () => {
  it("reads a declared file into a raw entry", async () => {
    const dir = home({
      "grenz.yaml": `agents:\n  - id: ci\n    token_hash: "${HASH}"\n    policy: ci-merge\npolicy_profiles:\n  ci-merge:\n    file: profiles/ci.yaml\n`,
      "policy.yaml": DEFAULT_POLICY,
      "profiles/ci.yaml": CI_PROFILE,
    });
    const loaded = await loadAll(dir);
    const e = loaded.entries.find((x) => x.name === "ci-merge");
    expect(e).toBeDefined();
    expect(e!.policy).toContain("pr:merge");
  });

  it("throws ConfigError when a profile file is missing", async () => {
    const dir = home({
      "grenz.yaml": `agents:\n  - id: ci\n    token_hash: "${HASH}"\n    policy: ci-merge\npolicy_profiles:\n  ci-merge:\n    file: profiles/missing.yaml\n`,
      "policy.yaml": DEFAULT_POLICY,
    });
    await expect(loadAll(dir)).rejects.toBeInstanceOf(ConfigError);
  });

  it("throws ConfigError when a profile file will not compile", async () => {
    const dir = home({
      "grenz.yaml": `agents:\n  - id: ci\n    token_hash: "${HASH}"\n    policy: ci-merge\npolicy_profiles:\n  ci-merge:\n    file: profiles/bad.yaml\n`,
      "policy.yaml": DEFAULT_POLICY,
      "profiles/bad.yaml": "this: is not a: valid policy",
    });
    await expect(loadAll(dir)).rejects.toBeInstanceOf(ConfigError);
  });

  it("returns no entries when no profiles configured", async () => {
    const dir = home({
      "grenz.yaml": `agents:\n  - id: legacy\n    token_hash: "${HASH}"\n`,
      "policy.yaml": DEFAULT_POLICY,
    });
    const loaded = await loadAll(dir);
    expect(loaded.entries.length).toBe(0);
  });

  it("a name-only declaration ({}) contributes no entry and does not throw", async () => {
    const dir = home({
      "grenz.yaml": `agents:\n  - id: ci\n    token_hash: "${HASH}"\n    policy: ci-remote\npolicy_profiles:\n  ci-remote: {}\n`,
      "policy.yaml": DEFAULT_POLICY,
    });
    const loaded = await loadAll(dir);
    expect(loaded.entries.length).toBe(0);
  });
});
