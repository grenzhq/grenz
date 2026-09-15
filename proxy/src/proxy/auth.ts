/**
 * Agent authentication.
 *
 * The agent presents its GRENZ_TOKEN via `Authorization: Bearer <token>` or
 * `X-Grenz-Token: <token>`. We hash it and constant-time compare against the
 * configured agents' stored hashes. No match -> null (the caller returns 401).
 *
 * The token is never logged and never forwarded upstream.
 */
import type { AgentConfig } from "../config/schema.ts";
import type { DelegationStore } from "../delegate/store.ts";
import { constantTimeEqual, hashToken } from "../util/token.ts";

/**
 * Who a request is acting as. Either a first-class agent, or a delegation — a
 * sub-agent spawned with an attenuated (strict-subset) scope, possibly several
 * hops deep. A delegation's `agentId` is the ROOT agent of its chain: it shares
 * that agent's policy and budget, and is cut off when the root agent OR any
 * grant in its chain is revoked (cascade). Its effective scope is the
 * intersection of every grant in the chain with the root's live policy.
 */
export type Principal =
  | {
      readonly kind: "agent";
      readonly agentId: string;
      readonly decoy: boolean;
      /** The agent's configured target globs, or `[]` when unrestricted. The
       * root scope every request (and every delegation minted here) answers to. */
      readonly agentTargets: readonly string[];
      /** The agent's configured action globs, or `[]` when unrestricted — the
       * other scope axis, same root-of-the-chain role as `agentTargets`. */
      readonly agentActions: readonly string[];
      /** The agent's configured profile name (a key of policy_profiles), or
       *  undefined for the default policy. Read at the decision site to select
       *  the compiled policy; travels on the principal so no config re-lookup. */
      readonly policyProfile?: string;
    }
  | {
      readonly kind: "delegation";
      /** The ROOT agent — shared policy + budget. */
      readonly agentId: string;
      /** The ROOT agent's own target globs (`[]` = unrestricted). Applied as the
       * root of the fold, so a sub-token can never exceed its agent's reach. */
      readonly agentTargets: readonly string[];
      /** The ROOT agent's own action globs (`[]` = unrestricted). Applied as the
       * root of the fold on the action axis, for the same reason. */
      readonly agentActions: readonly string[];
      /** The LEAF grant this token maps to — taint-flow session + per-delegation budget. */
      readonly delegationId: string;
      /** Every grant id in the chain, leaf → root. Revocation of ANY cuts this off. */
      readonly chainIds: readonly string[];
      /** Each grant's action patterns, leaf → root. Scope is their intersection
       * (the fold), so every hop must match a requested action. */
      readonly actionsChain: readonly (readonly string[])[];
      /** Each grant's target globs, leaf → root. A hop with no targets is
       * unrestricted; scope is the intersection of the hops that do constrain. */
      readonly targetsChain: readonly (readonly string[])[];
      /** The ROOT agent's profile, SNAPSHOTTED at mint (never a live config
       *  lookup) — so a root removed from config cannot widen this sub-token. */
      readonly policyProfile?: string;
    };

/** Extract a bearer token from the request headers, if present. */
export function extractToken(headers: Headers): string | null {
  const xheader = headers.get("x-grenz-token");
  if (xheader && xheader.trim().length > 0) return xheader.trim();

  const auth = headers.get("authorization");
  if (auth) {
    const match = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (match && match[1]) return match[1].trim();
  }
  return null;
}

/**
 * The outcome of resolving a presented token. `principal` is null on any miss
 * (unknown token, expired agent, expired/unknown delegation). `expiredAgentId`
 * is set ONLY when a token matched a configured agent that is past its
 * `expires_at`: the caller logs a distinct `agent_token_expired` reason while
 * returning the same generic 401 an unknown token gets. Expiry is enforced by
 * producing NO principal — a caller that ignores `expiredAgentId` loses a log
 * label, never authorization (fail-closed by omission).
 */
export interface Resolution {
  readonly principal: Principal | null;
  readonly expiredAgentId: string | null;
  /**
   * Set ONLY when a live delegation resolved but its ROOT agent is gone —
   * deleted from config, or past its own `expires_at`. Like `expiredAgentId`,
   * this is a log label on top of a null principal: enforcement is the missing
   * principal, so a caller that ignores it loses a reason code, never
   * authorization.
   */
  readonly orphanRootAgentId: string | null;
}

/**
 * Resolve a presented token to a Principal: first a first-class agent
 * (constant-time compare against each configured hash), else a live delegation
 * (looked up by hash; expired or unknown → miss). A matched-but-expired agent
 * falls through to the same delegation lookup and the same null exit as an
 * unknown token — identical code, differing only in the `expiredAgentId` label.
 */
export async function resolvePrincipal(
  agents: readonly AgentConfig[],
  delegations: DelegationStore | null,
  token: string | null,
  now: number,
): Promise<Resolution> {
  if (!token) return { principal: null, expiredAgentId: null, orphanRootAgentId: null };
  const hash = await hashToken(token);
  // Full loop, constant-time per compare, no early break — leaks nothing about
  // which token (if any) matched.
  let matched: AgentConfig | null = null;
  for (const agent of agents) {
    if (constantTimeEqual(hash, agent.token_hash)) {
      matched = agent;
    }
  }
  // Expiry is checked AFTER the loop (never inside), so it adds no
  // data-dependent branch beside the compares. Boundary: `=== now` is expired,
  // matching the delegation store's `<= now` convention.
  let expiredAgentId: string | null = null;
  if (matched) {
    if (matched.expiresAtMs !== null && matched.expiresAtMs <= now) {
      // Past expiry: this token is no identity. Fall through to the delegation
      // lookup and the same null exit — no revoke, no notifier (those are decoy
      // semantics), only a log label for the operator.
      expiredAgentId = matched.id;
    } else {
      return {
        principal: {
          kind: "agent",
          agentId: matched.id,
          decoy: matched.decoy,
          agentTargets: matched.targets ?? [],
          agentActions: matched.actions ?? [],
          policyProfile: matched.policy,
        },
        expiredAgentId: null,
        orphanRootAgentId: null,
      };
    }
  }

  const resolved = delegations?.resolveChain(hash, now);
  if (resolved) {
    const { chain, rootAgentId, policyProfile } = resolved;
    // The root agent's own scope is the outermost hop of the fold: a sub-token
    // attenuates from its agent's reach, never beyond it.
    //
    // A root that is GONE — deleted from config, or past its own expires_at —
    // is fail-closed, not "unconstrained". Falling back to `[]` (which means
    // unrestricted) would make deleting a scoped agent WIDEN its live children
    // instead of killing them; expiring one would do the same. `policyProfile`
    // is snapshotted at mint for exactly this reason — the scope axes now agree.
    const rootAgent = agents.find((a) => a.id === rootAgentId);
    const rootGone =
      rootAgent === undefined ||
      (rootAgent.expiresAtMs !== null && rootAgent.expiresAtMs <= now);
    if (rootGone) {
      return { principal: null, expiredAgentId, orphanRootAgentId: rootAgentId };
    }
    return {
      principal: {
        kind: "delegation",
        agentId: rootAgentId,
        agentTargets: rootAgent.targets ?? [],
        agentActions: rootAgent.actions ?? [],
        delegationId: chain[0]!.id, // the leaf (chain is leaf-first; guaranteed non-empty)
        chainIds: chain.map((d) => d.id),
        actionsChain: chain.map((d) => d.actions),
        targetsChain: chain.map((d) => d.targets),
        policyProfile,
      },
      expiredAgentId,
      orphanRootAgentId: null,
    };
  }
  return { principal: null, expiredAgentId, orphanRootAgentId: null };
}
