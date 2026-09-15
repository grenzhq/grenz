# RFC 0001 — Attenuated delegation semantics

**Status:** draft · **Scope:** proxy delegation (`proxy/src/delegate`, `proxy/src/proxy`)

Grenz lets an agent mint sub-tokens for the sub-agents it spawns — a reviewer,
a test-runner, a doc-writer — each scoped to a **strict subset** of the minter's
own authority, time-boxed and revocable, with no new human, no policy edit, and
no cloud round-trip. This RFC fixes the *semantics* of that delegation so they
are precise, testable, and portable to a future format. It deliberately
specifies **no wire format and no cryptography** (see Non-goals).

## Model

A **grant** records: the root agent it descends from, its immediate parent
(agent or grant), the action patterns it may touch, a note, and a TTL. Grants
form a **chain** from a leaf (the token a sub-agent presents) up to the root
agent. Every grant in the chain shares the root agent's identity for **policy
and budget** — a delegated request is the root agent acting through a narrower
aperture, never a new principal.

## The narrowing rule — intersection, not subset-checking

The scope of a delegated request is the **fold**:

```
effective = live_policy(root_agent)  ∩  grant₁  ∩  grant₂  ∩  …  ∩  grantₙ
```

computed **at request time**, where `grantᵢ` are the chain's grants from root to
leaf. Concretely, a requested action is in scope **iff the root agent's live
policy would allow it AND every grant in the chain matches it** (glob match, at
least one pattern per grant). The first out-of-scope action denies the whole
request with `delegation_scope` (403).

Two consequences, both load-bearing:

1. **A grant is a ceiling, never a floor.** Intersection is monotone: a grant
   (or a whole hop) that names something *broader* than its parent cannot widen
   anything — the narrower ancestor still has to match, and the live policy
   still has to allow. So a malicious or buggy intermediate hop that advertises
   `repo:write` when its parent only held `repo:read` grants nothing: `repo:write`
   fails the parent hop's match and is denied. **We never compute a merged
   pattern set and never test one glob as a subset of another** — glob-subset
   testing is where the bugs live; the fold sidesteps it entirely.
2. **The token is untrusted input.** Its advertised actions can only ever
   subtract. Enforcement lives in the request-time fold, not in what any grant
   claims at mint time. A mint-time breadth check, if added, is a courtesy lint —
   never the security boundary.

## Identity, budget, taint, pins

- **Identity / policy / agent budget:** the root agent. Delegated requests count
  against the root agent's ceiling (shared-quota invariant).
- **Per-delegation budget:** attributed to the **leaf** grant id.
- **Taint-flow session:** the leaf grant id (per-delegation isolation).
- **Pins:** a delegated request reads its own and **every ancestor's** pins (the
  whole chain plus the root agent), so a fresh grant id cannot escape a session
  pin set on an ancestor.

## Revocation — proxy-authoritative, cascade by chain

Revocation is a plain kill-list keyed by id (local, unioned with the signed
fleet set — the fleet set can never un-revoke a locally-cut id). A delegated
request is denied `token_revoked` if **any id in its chain** — the root agent or
any grant — is revoked, locally or in the fleet set. Therefore:

- Revoking the **root agent** cuts off the whole tree (every descendant carries
  the root id).
- Revoking **any grant** cuts off that grant and everything below it, leaving
  its ancestors and siblings alive.
- Cascade needs **no tree walk at revoke time**: it falls out of checking every
  chain id on each request. Revocation of a grant id is fleet-distributable
  (the fleet set is keyed by opaque id), fixing the prior local-only gap.

TTL is a second, passive kill path: a grant past its `expiresAt`, or any of
whose ancestors has expired or been purged, resolves to nothing (fail-closed). A
child's TTL is bounded by its parent's remaining TTL — a child can never outlive
its parent.

## Bounds

- **Chain depth** is capped (`MAX_DEPTH`). Minting at the cap is refused; a chain
  that exceeds it at resolve time fails closed.
- **Active grants** are capped (`MAX_ACTIVE`), so a compromised parent cannot
  spawn unboundedly.
- **TTL** is capped (`MAX_TTL_SECONDS`); a grant never outlives the hour.

## Non-goals (the bright line, rendered as MUSTs)

Grants are **live, forward-looking authorization state** — the answer to "may
this happen next," never a record of what happened. Therefore:

- A grant that can no longer authorize a future action (expired, revoked, past
  depth) **MUST NOT** be retained or made verifiable. The kill-list and the grant
  store are truncatable operational state, not history.
- The request log **MUST NOT** store grant contents or chain structure — only an
  opaque grant id, exactly as it stores an agent id today. No column exists for
  more.
- Grenz **MUST NOT** build a signed or tamper-evident chain over request history,
  or frame delegation as provenance, audit, or evidence. Signing a *pre-action
  grant* (a future, portable capability) is permitted; retaining a *verifiable
  record of past delegations* is not. If a design step needs the latter, stop.

## Deferred

A portable, offline-attenuable **wire format** (so a non-Grenz framework can
mint a narrower grant locally and any Grenz-compatible verifier accepts it) is
the only thing that turns these semantics into a standard others implement. It
is deferred until a second implementer actually needs it; when that arrives, the
likely path is a **profile of an existing capability format** (e.g. Biscuit —
public-key, offline-attenuable, restrict-only) carrying these semantics, rather
than a bespoke format. Publishing a format before adoption produces a document,
not a moat; the semantics above are the durable contribution.
