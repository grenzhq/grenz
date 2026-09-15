/**
 * DelegationStore persists and reloads a grant's target attenuation, and
 * treats a pre-target-scoping record (no `targets` field) as unrestricted —
 * so upgrading the binary never silently narrows an existing delegation.
 */
import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DelegationStore } from "../src/delegate/store.ts";

let tmp: string;
let path: string;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "grenz-deltgt-"));
  path = join(tmp, "delegations.json");
});
afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

describe("DelegationStore — targets", () => {
  test("mint records targets and they survive a reload", async () => {
    const store = new DelegationStore(path);
    const { token, delegation } = await store.mint({
      parentAgentId: "claude-code",
      actions: ["repo:read"],
      targets: ["/repos/o/*", "/repos/team/app"],
      ttlMs: 900_000,
      note: "",
      now: 1000,
    });
    expect(delegation.targets).toEqual(["/repos/o/*", "/repos/team/app"]);

    // A fresh store reading the same file sees the same targets.
    const reloaded = new DelegationStore(path);
    const hash = await (async () => {
      const { hashToken } = await import("../src/util/token.ts");
      return hashToken(token);
    })();
    const got = reloaded.resolve(hash, 1000);
    expect(got?.targets).toEqual(["/repos/o/*", "/repos/team/app"]);
  });

  test("omitting targets yields an empty (unrestricted) list", async () => {
    const store = new DelegationStore(path);
    const { delegation } = await store.mint({
      parentAgentId: "claude-code",
      actions: ["repo:read"],
      ttlMs: 900_000,
      note: "",
      now: 1000,
    });
    expect(delegation.targets).toEqual([]);
  });

  test("a legacy record with no targets field loads as unrestricted", async () => {
    // Simulate a file written by a pre-target-scoping binary.
    const legacy = {
      version: 1,
      delegations: {
        del_legacy: {
          parentAgentId: "claude-code",
          parentDelegationId: null,
          tokenHash: "a".repeat(64),
          actions: ["repo:read"],
          note: "",
          createdAt: 1000,
          expiresAt: 9_999_999_999_999,
        },
      },
    };
    await writeFile(path, JSON.stringify(legacy));
    const store = new DelegationStore(path);
    const got = store.resolve("a".repeat(64), 2000);
    expect(got).not.toBeNull();
    expect(got?.targets).toEqual([]); // absent field → unrestricted, not undefined
  });
});
