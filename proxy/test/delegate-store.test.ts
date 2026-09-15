import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, readFileSync } from "node:fs";
import { DelegationStore, DelegationError, MAX_DEPTH } from "../src/delegate/store.ts";
import { hashToken } from "../src/util/token.ts";

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "grenz-del-"));
  path = join(dir, "delegations.json");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const mint = (s: DelegationStore, over?: Partial<{ actions: string[]; ttlMs: number; note: string; now: number; parent: string }>) =>
  s.mint({
    parentAgentId: over?.parent ?? "claude-code",
    actions: over?.actions ?? ["repo:read"],
    ttlMs: over?.ttlMs ?? 60_000,
    note: over?.note ?? "",
    now: over?.now ?? 1000,
  });

describe("DelegationStore", () => {
  test("mint returns a token that resolves back to the delegation", async () => {
    const s = new DelegationStore(path);
    const { token, delegation } = await mint(s, { actions: ["repo:read", "pr:read"] });
    const resolved = s.resolve(await hashToken(token), 2000);
    expect(resolved?.id).toBe(delegation.id);
    expect(resolved?.parentAgentId).toBe("claude-code");
    expect(resolved?.actions).toEqual(["repo:read", "pr:read"]);
  });

  test("an expired delegation does not resolve", async () => {
    const s = new DelegationStore(path);
    const { token } = await mint(s, { ttlMs: 1000, now: 1000 }); // expires at 2000
    expect(s.resolve(await hashToken(token), 1500)).not.toBeNull();
    expect(s.resolve(await hashToken(token), 2000)).toBeNull(); // at expiry
    expect(s.resolve(await hashToken(token), 9999)).toBeNull();
  });

  test("an unknown token hash does not resolve", async () => {
    const s = new DelegationStore(path);
    await mint(s);
    expect(s.resolve(await hashToken("not-a-real-token"), 2000)).toBeNull();
  });

  test("persists across reopen (a restart still honors live tokens)", async () => {
    const s = new DelegationStore(path);
    const { token } = await mint(s, { actions: ["issue:read"], ttlMs: 60_000, now: 1000 });
    const reopened = new DelegationStore(path);
    const resolved = reopened.resolve(await hashToken(token), 2000);
    expect(resolved?.actions).toEqual(["issue:read"]);
  });

  test("the plaintext token is NEVER written to disk — only its hash", async () => {
    const s = new DelegationStore(path);
    const { token } = await mint(s);
    const onDisk = readFileSync(path, "utf8");
    expect(onDisk).not.toContain(token);
    expect(onDisk).toContain(await hashToken(token)); // the hash is what's stored
  });

  test("list is newest-first and excludes expired", async () => {
    const s = new DelegationStore(path);
    await mint(s, { actions: ["a"], now: 1000, ttlMs: 60_000 });
    await mint(s, { actions: ["b"], now: 2000, ttlMs: 60_000 });
    await mint(s, { actions: ["c"], now: 500, ttlMs: 100 }); // expired by now=3000
    const live = s.list(3000);
    expect(live.map((d) => d.actions[0])).toEqual(["b", "a"]);
  });

  test("purgeExpired drops dead records and persists", async () => {
    const s = new DelegationStore(path);
    await mint(s, { ttlMs: 100, now: 1000 }); // expires 1100
    await mint(s, { ttlMs: 60_000, now: 1000 });
    expect(s.purgeExpired(5000)).toBe(1);
    expect(new DelegationStore(path).list(5000).length).toBe(1);
  });

  test("corrupt file throws DelegationError (fail closed)", () => {
    writeFileSync(path, "not json at all");
    expect(() => new DelegationStore(path)).toThrow(DelegationError);
  });

  test("distinct tokens are minted per delegation", async () => {
    const s = new DelegationStore(path);
    const a = await mint(s);
    const b = await mint(s);
    expect(a.token).not.toBe(b.token);
    expect(a.delegation.id).not.toBe(b.delegation.id);
  });
});

describe("DelegationStore — multi-hop chains", () => {
  /** Mint one grant whose immediate parent is `parentDelegationId` (null = agent). */
  const hop = (
    s: DelegationStore,
    parentDelegationId: string | null,
    over?: Partial<{ actions: string[]; ttlMs: number; now: number; agent: string }>,
  ) =>
    s.mint({
      parentAgentId: over?.agent ?? "claude-code",
      parentDelegationId,
      actions: over?.actions ?? ["repo:read"],
      ttlMs: over?.ttlMs ?? 60_000,
      note: "",
      now: over?.now ?? 1000,
    });

  test("a child links to its parent grant and resolveChain returns the chain leaf-first", async () => {
    const s = new DelegationStore(path);
    const root = await hop(s, null, { actions: ["repo:*"] });
    const child = await hop(s, root.delegation.id, { actions: ["repo:read"] });
    const got = s.resolveChain(await hashToken(child.token), 2000);
    expect(got).not.toBeNull();
    expect(got!.chain.map((d) => d.id)).toEqual([child.delegation.id, root.delegation.id]);
    expect(got!.rootAgentId).toBe("claude-code");
    expect(child.delegation.parentDelegationId).toBe(root.delegation.id);
  });

  test("an agent-minted grant is a one-element chain rooted at the agent", async () => {
    const s = new DelegationStore(path);
    const root = await hop(s, null, { agent: "builder" });
    const got = s.resolveChain(await hashToken(root.token), 2000);
    expect(got!.chain).toHaveLength(1);
    expect(got!.rootAgentId).toBe("builder");
    expect(root.delegation.parentDelegationId).toBeNull();
  });

  test("an EXPIRED ancestor kills every descendant (fail closed)", async () => {
    const s = new DelegationStore(path);
    // parent expires at 1500; child would live to 61000 on its own.
    const root = await hop(s, null, { ttlMs: 500, now: 1000 }); // expires 1500
    const child = await hop(s, root.delegation.id, { ttlMs: 60_000, now: 1000 });
    const hash = await hashToken(child.token);
    expect(s.resolveChain(hash, 1400)).not.toBeNull(); // both live
    expect(s.resolveChain(hash, 1500)).toBeNull(); // parent dead at its expiry
    expect(s.resolveChain(hash, 2000)).toBeNull();
  });

  test("a MISSING ancestor makes the chain fail closed", async () => {
    const s = new DelegationStore(path);
    const child = await hop(s, "del_nonexistent", { actions: ["repo:read"] });
    expect(s.resolveChain(await hashToken(child.token), 2000)).toBeNull();
  });

  test("a chain of exactly MAX_DEPTH resolves; one deeper fails closed", async () => {
    const s = new DelegationStore(path);
    let parentId: string | null = null;
    const tokens: string[] = [];
    for (let i = 0; i < MAX_DEPTH; i++) {
      const g = await hop(s, parentId, { now: 1000, ttlMs: 60_000 });
      parentId = g.delegation.id;
      tokens.push(g.token);
    }
    // The deepest grant (chain length exactly MAX_DEPTH) resolves.
    const deepest = s.resolveChain(await hashToken(tokens[tokens.length - 1]!), 2000);
    expect(deepest!.chain).toHaveLength(MAX_DEPTH);
    // One hop further would make length MAX_DEPTH+1 → fail closed.
    const tooDeep = await hop(s, parentId, { now: 1000, ttlMs: 60_000 });
    expect(s.resolveChain(await hashToken(tooDeep.token), 2000)).toBeNull();
  });

  test("records written before multi-hop load as root grants (back-compat)", async () => {
    // Simulate an old file with no parentDelegationId field.
    const legacy = {
      version: 1,
      delegations: {
        del_old: {
          parentAgentId: "claude-code",
          tokenHash: await hashToken("legacy-token"),
          actions: ["repo:read"],
          note: "",
          createdAt: 1000,
          expiresAt: 9_000_000,
        },
      },
    };
    writeFileSync(path, JSON.stringify(legacy));
    const s = new DelegationStore(path);
    const got = s.resolveChain(await hashToken("legacy-token"), 2000);
    expect(got!.chain).toHaveLength(1);
    expect(got!.chain[0]!.parentDelegationId).toBeNull();
    expect(got!.rootAgentId).toBe("claude-code");
  });
});
