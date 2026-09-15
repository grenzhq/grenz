/**
 * Delegation store — attenuated sub-tokens for spawned sub-agents.
 *
 * The problem this solves: an agent holding a GRENZ_TOKEN spawns helpers (a
 * reviewer, a test-runner, a doc-writer). Without delegation they'd all share
 * the one token — the full scope. Real IAM for the agent era needs a parent to
 * hand a child a STRICT SUBSET of its own powers, time-boxed and revocable,
 * with no new human, no policy edit, and no cloud round-trip.
 *
 * A delegation carries an ATTENUATION: a set of action patterns the child may
 * touch. The guarantee is macaroon-style — attenuation can only NARROW. The
 * child's every request is still evaluated against the parent's live policy, so
 * a child can never gain an action the parent lacks even if its token advertises
 * one. Enforcement is the intersection (policy ∩ attenuation), checked on each
 * request; this store only records the grant.
 *
 * Like the request log and the kill-list, this is plain, truncatable JSON —
 * operational state, not tamper-evident and not a credential. Only the child
 * token's SHA-256 HASH is stored; the plaintext is shown once at mint time and
 * never persisted or logged. A corrupt file THROWS on load so the proxy refuses
 * to serve with an unknown delegation set (fail closed).
 */
import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { z } from "zod";
import { generateToken, hashToken } from "../util/token.ts";
import { shortId } from "../util/id.ts";

export const MAX_TTL_SECONDS = 3600; // a delegation never outlives the hour
export const DEFAULT_TTL_SECONDS = 900; // 15 minutes
const MAX_NOTE = 200;
const MAX_ACTIONS = 100;
const MAX_TARGETS = 100;
/** Bounds memory/disk so a compromised parent can't spawn children unboundedly. */
export const MAX_ACTIVE = 1000;
/**
 * Max grants in a delegation chain (root grant → leaf). Bounds the request-time
 * fold and stops a runaway re-delegation loop. A chain longer than this fails
 * closed at resolve time; minting at the cap is refused.
 */
export const MAX_DEPTH = 5;

export interface Delegation {
  readonly id: string;
  /** The ROOT agent this chain descends from — shared by every grant in the
   * chain for policy and budget. A delegated request is the root agent acting
   * through a narrower aperture, never a new principal. */
  readonly parentAgentId: string;
  /** The IMMEDIATE parent grant, or null when minted directly by an agent.
   * This is what links a grant into a multi-hop chain. */
  readonly parentDelegationId: string | null;
  /** SHA-256 of the child token. The plaintext is never stored. */
  readonly tokenHash: string;
  /** Action patterns the child may touch (a subset of the parent's scope). */
  readonly actions: readonly string[];
  /** Target globs the child may reach (a subset of the parent's reach). Empty =
   * unrestricted by THIS grant — the request target still has to satisfy every
   * OTHER hop that constrains it, and the root's live policy. */
  readonly targets: readonly string[];
  /** The root agent's policy profile, SNAPSHOTTED at mint (like scope). Resolution
   *  never re-looks-up the root agent, so deleting the agent from config cannot
   *  widen this sub-token to the default policy. Undefined = default. */
  readonly policyProfile?: string;
  readonly note: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

/** The `/delegate` request body (agent self-mint). Validated at the boundary. */
export const delegateRequestSchema = z
  .object({
    actions: z.array(z.string().min(1)).min(1).max(MAX_ACTIONS),
    targets: z.array(z.string().min(1)).min(1).max(MAX_TARGETS).optional(),
    ttl_seconds: z.number().int().positive().max(MAX_TTL_SECONDS).optional(),
    note: z.string().max(MAX_NOTE).optional(),
  })
  .strict();

export class DelegationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DelegationError";
  }
}

interface StoredShape {
  version: number;
  delegations: Record<string, Omit<Delegation, "id">>;
}

export interface MintInput {
  /** The ROOT agent id — inherited unchanged down the chain. */
  readonly parentAgentId: string;
  /** The immediate parent grant, or null when an agent mints directly. */
  readonly parentDelegationId?: string | null;
  readonly actions: readonly string[];
  /** Target globs the child may reach. Omit/empty = unrestricted by this grant. */
  readonly targets?: readonly string[];
  /** The profile to snapshot: the minting AGENT's `policy` for a level-1 mint, the
   *  parent DELEGATION's `policyProfile` for a nested one. Undefined = default. */
  readonly policyProfile?: string;
  readonly ttlMs: number;
  readonly note: string;
  readonly now: number;
}

export class DelegationStore {
  private readonly path: string;
  private byId: Map<string, Delegation>;
  private hashToId: Map<string, string>;

  constructor(path: string) {
    this.path = path;
    this.byId = DelegationStore.load(path);
    this.hashToId = new Map();
    for (const d of this.byId.values()) this.hashToId.set(d.tokenHash, d.id);
  }

  /**
   * Mint a child token. Returns the plaintext token ONCE — the caller shows it
   * to the delegator and forgets it; only the hash is retained.
   */
  async mint(input: MintInput): Promise<{ token: string; delegation: Delegation }> {
    const token = generateToken("grenz-del"); // grenz delegation token
    const tokenHash = await hashToken(token);
    const delegation: Delegation = {
      id: shortId("del"),
      parentAgentId: input.parentAgentId,
      parentDelegationId: input.parentDelegationId ?? null,
      tokenHash,
      actions: [...input.actions].slice(0, MAX_ACTIONS),
      targets: [...(input.targets ?? [])].slice(0, MAX_TARGETS),
      ...(input.policyProfile !== undefined ? { policyProfile: input.policyProfile } : {}),
      note: input.note.slice(0, MAX_NOTE),
      createdAt: input.now,
      expiresAt: input.now + input.ttlMs,
    };
    this.byId.set(delegation.id, delegation);
    this.hashToId.set(tokenHash, delegation.id);
    this.persist();
    return { token, delegation };
  }

  /** True when the live-delegation count is at the cap (mint should refuse). */
  atCapacity(now: number): boolean {
    return this.list(now).length >= MAX_ACTIVE;
  }

  /** Resolve a token hash to a live delegation, or null if unknown or expired. */
  resolve(tokenHash: string, now: number): Delegation | null {
    const id = this.hashToId.get(tokenHash);
    if (!id) return null;
    const d = this.byId.get(id);
    if (!d) return null;
    if (d.expiresAt <= now) return null; // expired = dead
    return d;
  }

  /**
   * Walk a grant's chain from itself up to its root grant, leaf-first. Returns
   * null (fail-closed) if the grant is unknown, if ANY hop is expired or missing
   * (an expired/purged ancestor kills every descendant), or if the chain would
   * exceed {@link MAX_DEPTH}. A live single (agent-minted) grant returns a
   * one-element chain.
   */
  chainById(id: string, now: number): Delegation[] | null {
    const chain: Delegation[] = [];
    let curId: string | null = id;
    while (curId !== null) {
      if (chain.length >= MAX_DEPTH) return null; // one more hop would exceed the cap
      const cur = this.byId.get(curId);
      if (!cur) return null; // unknown leaf, or an ancestor purged out from under us
      if (cur.expiresAt <= now) return null; // any dead hop kills the chain
      chain.push(cur);
      curId = cur.parentDelegationId;
    }
    return chain.length > 0 ? chain : null;
  }

  /**
   * Resolve a token hash to its full live chain plus the root agent id. The
   * request path uses this: `agentId` is the root agent (policy + budget), and
   * every grant's actions are folded (intersection) at request time.
   * Also returns the root grant's snapshotted `policyProfile` (undefined when
   * none was set at mint time).
   */
  resolveChain(
    tokenHash: string,
    now: number,
  ): { chain: Delegation[]; rootAgentId: string; policyProfile?: string } | null {
    const id = this.hashToId.get(tokenHash);
    if (!id) return null;
    const chain = this.chainById(id, now);
    if (!chain) return null;
    // Every grant carries the root agent id (inherited at mint); read it off the
    // leaf (chainById guarantees a non-empty chain). The top grant's
    // parentDelegationId is null by construction.
    const root = chain[chain.length - 1]!; // root grant (parentDelegationId === null)
    return { chain, rootAgentId: chain[0]!.parentAgentId, policyProfile: root.policyProfile };
  }

  get(id: string): Delegation | undefined {
    return this.byId.get(id);
  }

  /** Active (non-expired) delegations, newest first. */
  list(now: number): Delegation[] {
    return [...this.byId.values()]
      .filter((d) => d.expiresAt > now)
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  /** Drop expired records and rewrite the file. Returns how many were purged. */
  purgeExpired(now: number): number {
    let purged = 0;
    for (const [id, d] of this.byId) {
      if (d.expiresAt <= now) {
        this.byId.delete(id);
        this.hashToId.delete(d.tokenHash);
        purged++;
      }
    }
    if (purged > 0) this.persist();
    return purged;
  }

  private persist(): void {
    const shape: StoredShape = { version: 1, delegations: {} };
    for (const d of this.byId.values()) {
      shape.delegations[d.id] = {
        parentAgentId: d.parentAgentId,
        parentDelegationId: d.parentDelegationId,
        tokenHash: d.tokenHash,
        actions: d.actions,
        targets: d.targets,
        ...(d.policyProfile !== undefined ? { policyProfile: d.policyProfile } : {}),
        note: d.note,
        createdAt: d.createdAt,
        expiresAt: d.expiresAt,
      };
    }
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(shape, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  private static load(path: string): Map<string, Delegation> {
    if (!existsSync(path)) return new Map();
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new DelegationError(`delegations file is not valid JSON: ${path}`);
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new DelegationError(`delegations file is malformed: ${path}`);
    }
    const dels = (parsed as Record<string, unknown>).delegations;
    if (typeof dels !== "object" || dels === null) {
      throw new DelegationError(`delegations file is malformed: ${path}`);
    }
    const map = new Map<string, Delegation>();
    for (const [id, raw] of Object.entries(dels as Record<string, unknown>)) {
      if (typeof raw !== "object" || raw === null) continue;
      const r = raw as Record<string, unknown>;
      if (typeof r.tokenHash !== "string" || typeof r.parentAgentId !== "string") continue;
      const actions = Array.isArray(r.actions)
        ? r.actions.filter((a): a is string => typeof a === "string")
        : [];
      // Back-compat: records written before target scoping have no field →
      // an unrestricted (by-target) grant.
      const targets = Array.isArray(r.targets)
        ? r.targets.filter((t): t is string => typeof t === "string")
        : [];
      map.set(id, {
        id,
        parentAgentId: r.parentAgentId,
        // Back-compat: records written before multi-hop have no field → a root
        // grant (minted directly by an agent).
        parentDelegationId: typeof r.parentDelegationId === "string" ? r.parentDelegationId : null,
        tokenHash: r.tokenHash,
        actions,
        targets,
        // Back-compat: records written before per-agent policy have no field.
        policyProfile: typeof r.policyProfile === "string" ? r.policyProfile : undefined,
        note: typeof r.note === "string" ? r.note : "",
        createdAt: typeof r.createdAt === "number" ? r.createdAt : 0,
        expiresAt: typeof r.expiresAt === "number" ? r.expiresAt : 0,
      });
    }
    return map;
  }
}
