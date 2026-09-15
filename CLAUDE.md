# CLAUDE.md — Grenz

Agent-aware access control: scoped, revocable, observable permissions
for AI agents acting on behalf of humans. This is the missing IAM layer
for the agent era.

This file is the contributor guide and the contract for any agent (or
human) working in this repo: the principles below are load-bearing, not
aspirational.

## What Grenz is (and is not)

Grenz is **pre-action permissioning**: "may this agent do X right now?"
Grenz is NOT post-action audit evidence, tamper-evident logging, or
compliance tooling.

### Bright-line rules — never violate, even if a feature request points there
- NEVER build tamper-evident/cryptographically-signed logs (no Merkle
  trees, no signature chains over request history). The local request
  log is operational visibility only: plain SQLite, truncatable, no
  integrity guarantees — that is a feature, not a gap.
- NEVER frame anything as "compliance evidence," "audit trail," or
  EU AI Act tooling — not in code comments, docs, or marketing copy.
- If a task seems to require either of the above, STOP and flag it for
  human review instead of building.

## Stack & conventions

- **Proxy**: TypeScript on Bun, compiled to single binary. No runtime
  deps that break `bun build --compile`.
- **Policies**: YAML source → compiled to a deterministic rule object.
  Policy evaluation must be pure, synchronous, and unit-testable —
  no network calls inside the policy engine, ever.
- **Credential vault v0**: age-encrypted local file. Design the vault
  behind an interface (`CredentialStore`) so 1Password/Vault backends
  slot in later without touching call sites.
- Strict TypeScript everywhere. No `any`. Zod at all IO boundaries.
- Tests: Bun test for proxy + policy engine. Policy engine has table-
  driven tests: every allow/deny/approval path in the spec gets a case.
- Errors: deny-by-default. An unmatchable request, a malformed policy,
  a vault failure — all resolve to DENY with a structured reason code.

## Architecture invariants

1. Real credentials exist ONLY inside the proxy. They never appear in
   logs, error messages, approval payloads, or the cloud plane.
2. The agent holds only a GRENZ_TOKEN. If code ever passes an upstream
   credential toward the agent, that is a critical bug.
3. Policy engine is embedded in the proxy (no network hop on the
   decision path). Cloud plane distributes policies; it never decides.
4. Approvals: `require_approval` actions block, push to Slack/CLI,
   TTL 5 minutes, expire → DENY.
5. Everything cloud-side is org-scoped with RLS. Aggregate stats only —
   no raw request bodies leave the proxy.

## Definition of done (every PR)
- Deny-by-default verified by a test
- No credential material in any log line or error path (grep-checked)
- Policy engine changes: table-driven test added
- Docs updated if any user-facing surface changed

## Ambition note
Within these guardrails, build so this becomes the standard: clean
extension points, a policy format worth imitating, and adapter
interfaces a community can implement.
