# Grenz

### Your agent spawns agents. Grenz decides what they may do.

Scoped, revocable permissions for AI agents and the sub-agents they spawn —
authority that can only narrow as work is handed down.

[![CI](https://github.com/grenzhq/grenz/actions/workflows/ci.yml/badge.svg)](https://github.com/grenzhq/grenz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**After one command, your agent literally does not have your token.**

```bash
curl -fsSL https://github.com/grenzhq/grenz/releases/latest/download/install.sh | sh
printf %s "$GITHUB_TOKEN" | grenz protect
```

That's it — no YAML to write. Your token moves into an encrypted vault, a safe
default policy is generated for you (irreversible actions — merge, delete, CI
changes — pause for your approval; everything else flows and is logged), and
you're told exactly how to point your agent at Grenz.

```bash
grenz demo-attack     # see what a tightly-scoped token still can't do, in ~1 second
grenz demo-handoff    # watch a sub-agent four hops down get refused a merge its lead can do
```

---

Your agent authenticates as *you* — with *your* full GitHub token, *your* Linear
access, *your* everything. IAM has no concept of "this is my agent: it may read
repos and open PRs, but never merge, never delete, never touch CI." **Grenz is
that missing layer.**

Grenz is a local proxy between an agent and the tools it uses. The agent gets a
`GRENZ_TOKEN`; the real credentials stay inside the proxy. Every request is
checked against a policy *before* it happens, the real credential is injected
only if the policy allows it, and risky actions can block for a human's approval.

Grenz is **pre-action permissioning** — "may this agent do X right now?" It is
not an audit log and makes no tamper-evidence or compliance claims; the local
request log is plain, truncatable SQLite for operational visibility only.

---

## Authority can only narrow

A lead agent spawns a triager, which spawns a fixer, which spawns something that
commits. Authenticating each of them is the easy half, and it is the half the
industry has solved — what nobody constrains is *what one agent hands to the
next*, so the agent at the end of the chain acts with the authority of the one
at the top.

In Grenz authority can only ever narrow. A parent mints a sub-token that is a
strict subset of its own scope, and every request is evaluated as the live
policy **intersected with every hop it travelled**. A descendant that claims
more than its parent held gains nothing by claiming it — an intersection cannot
grow. Chains are depth-capped, each hop expires within the hour, and revoking
any ancestor kills everything below it.

```
$ grenz demo-handoff

  lead        merge the PR               allow
  committer   merge the PR               deny   delegation_scope
  its child   merge the PR               deny   delegation_scope
```

The lead really is allowed to merge — the policy says so. What the committer
lacked was not permission but authority in the chain.

---

## Free vs. paid

Everything in this repo is MIT, and stays MIT: the proxy, the policy engine,
approvals, the credential vault (age file or HashiCorp Vault), tripwires,
break-glass, named admin tokens with roles, signed policy distribution, fleet
revocation — all of it. **If a human is at the keyboard, Grenz is free. Forever.**

We plan to charge for one thing: a hosted control plane for **headless** agents —
fleets running in CI and cron with nobody watching. That's an always-on approval
queue with mobile push, agents bound to your identity provider (offboard the
human, their agents die with them), and a hosted CI enforcement point so secrets
never touch the runner. You can't self-host "always-on," which is exactly why
it's the paid part. See [docs/enterprise.md](docs/enterprise.md).

**Nothing that is in this repo today will ever move behind a paywall.**

---

## Install

**curl** (downloads the release binary for your platform):

```bash
curl -fsSL https://github.com/grenzhq/grenz/releases/latest/download/install.sh | sh
```

The installer verifies the downloaded binary against the release's
`SHA256SUMS.txt` and **refuses to install if it can't** — a missing checksums
file, a missing entry for your platform, or no SHA-256 tool on the box each
abort with an explanation rather than installing something unchecked.
(`GRENZ_INSECURE_SKIP_VERIFY=1` overrides that, loudly, if you need it.)

`SHA256SUMS.txt` is itself signed with [cosign](https://docs.sigstore.dev)
in keyless mode, so you can check it came from this repo's release workflow and
not from someone who reached the release page:

```bash
cosign verify-blob SHA256SUMS.txt \
  --signature SHA256SUMS.txt.sig --certificate SHA256SUMS.txt.pem \
  --certificate-identity-regexp '^https://github\.com/grenzhq/grenz/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**Docker** (runs non-root; secrets live in a named volume, never in the image):

```bash
docker build -t grenz .
docker volume create grenz-data
docker run --rm -it -v grenz-data:/data grenz init            # prints your GRENZ_TOKEN
printf %s "$GITHUB_TOKEN" | docker run --rm -i -v grenz-data:/data grenz vault set github_token
docker run --rm -it -v grenz-data:/data -p 127.0.0.1:8787:8787 grenz   # loopback-only, like `grenz run`
```

The container listens on `0.0.0.0` internally (so Docker can forward to it), so
publish it as `-p 127.0.0.1:8787:8787` — **not** `-p 8787:8787`, which binds the
host's `0.0.0.0` and exposes the proxy to your whole LAN. A GRENZ_TOKEN is a
bearer token: anyone who can reach the port and holds a token is that agent.
Keep Grenz on loopback (its `grenz run` default) unless you deliberately front
it with TLS and network controls.

**From source** (requires [Bun](https://bun.sh)):

```bash
git clone https://github.com/grenzhq/grenz && cd grenz
bun install
cd proxy && bun run build      # -> ./proxy/dist/grenz (single binary)
```

## Quickstart (GitHub in ~2 minutes)

```bash
grenz init                                             # scaffold + print your GRENZ_TOKEN once
printf %s "$GITHUB_TOKEN" | grenz vault set github_token   # real token, from stdin
grenz run                                              # http://127.0.0.1:8787
```

Point any GitHub client at Grenz, using the `GRENZ_TOKEN` as its "token":

```bash
curl -H "Authorization: Bearer $GRENZ_TOKEN" \
     http://127.0.0.1:8787/u/github/repos/octocat/hello-world          # → 200 (repo:read)

curl -X PUT -H "Authorization: Bearer $GRENZ_TOKEN" \
     http://127.0.0.1:8787/u/github/repos/octocat/hello-world/pulls/1/merge
#   → 403  { "reason": "explicit_deny", "action": "pr:merge" }
```

Everything lives under `./.grenz/` (override with `--home` or `$GRENZ_HOME`).
There's a full [5-minute MCP quickstart](docs/quickstart.md) too.

Grenz can also gate the agent's own shell. `grenz hook` runs as a Claude Code
`PreToolUse` hook and checks every `Bash` command against your policy before it
runs — see [Guarding an agent's shell commands](docs/bash-guard.md).

Running a headless, always-on agent like [OpenClaw](https://docs.openclaw.ai)?
See [Put an OpenClaw agent behind Grenz](docs/openclaw.md) — same wrap, plus
phone approvals via [Relay](docs/relay.md) for the box with no keyboard.

## One home, many agents (do this)

The two-minute quickstart drops a home in `./.grenz` — fine for a first look, but
**for real use, run ONE home and ONE proxy outside all your repos**, and point
every agent at it:

```bash
export GRENZ_HOME="$HOME/.grenz"   # put this in your shell profile
grenz init
grenz run                          # one proxy for the whole fleet
```

Two reasons, both load-bearing:

- **Secret placement.** The home holds the age identity, `vault.age`, and the
  admin token. A per-repo `./.grenz` puts all of that *inside a worktree the
  agent can read* — so the very agent Grenz is firewalling could open its own
  vault and recover the real credential, defeating the point. A home outside
  every worktree is the boundary. (`grenz init` prints a loud warning when it
  detects a home inside a git repo — heed it.)
- **One policy, one kill-switch.** Every agent that authenticates to a proxy is
  evaluated by that proxy's single `policy.yaml`, and `grenz revoke <agent>`
  cuts one off fleet-wide. That shared policy is the baseline, **not a ceiling
  you're stuck with**: give each agent its own `actions:`/`targets:` scope (see
  [Agent scope](#agent-scope--confine-a-standing-agent)) so a read-only reviewer
  and a deploy agent can share the proxy while reaching very different things.
  Reach for a *separate* home only to wall off a different GitHub account/org, or
  for CI (a per-job ephemeral home). Keep the proxy up across reboots with
  [`grenz service`](#keeping-it-running--grenz-service).

## How it works

```
  Agent (Claude Code / MCP client / any HTTP tool)
    holds: GRENZ_TOKEN only
        │  HTTP, base URL points at Grenz
        ▼
  Grenz proxy  http://127.0.0.1:8787
    • authenticate the GRENZ_TOKEN            → which agent is this?
    • map the request to an action             GET /repos/o/r  → repo:read
    • evaluate the policy (pure, embedded)     deny > require_approval > allow
    • require_approval? block for a human (or the TTL expires → DENY)
    • check the hourly budget (counted in actions)
    • inject the REAL credential  ── outbound only ──▶  GitHub / Linear / Slack / MCP
    • log the decision (no secrets, ever)
```

The real credential appears in exactly one place — the outbound request to the
upstream — and never on the response handed back to the agent.

## Policy

`policy.yaml` is **deny-by-default**: anything not explicitly allowed is denied.
Precedence within a grant is **deny → require_approval → allow**.

A `deny` rule can carry an optional `message` — a remediation hint surfaced to
the agent (response body `hint` + the `x-grenz-hint` header) so it learns *why*
it was blocked and what to do instead, rather than blindly retrying:

```yaml
    deny:
      - action: pr:merge
        message: "Direct merges are disabled — open a PR and request review in #eng."
```

The message is static policy text you author (never request data), so it is
log-safe and never carries a credential. It annotates a deny; it never changes a
decision.

```yaml
agent: claude-code
on_behalf_of: you@example.com
grants:
  - tool: github
    allow:
      - repo:read
      - pr:read
      - pr:comment
      - issue:read
      - issue:create
      # target-scoped: this rule applies only where its targets glob matches
      - action: pr:create
        targets: ["/repos/acme/*"]
    deny:  [pr:merge, repo:delete, "actions:*"]
    require_approval: [issue:update]
budget:
  max_actions_per_hour: 200   # default ceiling, per agent
  per_upstream:               # optional per-tool ceilings
    github: 100               # one noisy tool can't starve the rest
  per_agent:                  # optional per-agent ceilings
    ci-bot: 20                # this agent's ceiling instead of the default
  per_delegation: 20          # optional: EACH delegated sub-token capped individually
  weights:                    # optional: make risky actions cost more (see below)
    "repo:delete": 25
    "pr:merge": 10
approvals:
  per_agent:                  # optional: for a named agent, these actions need a
    ci-bot:                   # human nod — even where the grants above allow them
      - "*:delete"            # any target
      - { action: "pr:merge", targets: ["/repos/acme/prod-*"] }  # only on prod repos
```

Budgets are counted in cost units (default: one action costs 1, and an MCP
batch bills the sum of its members) over a rolling hour, and each agent is
counted separately. `max_actions_per_hour` is the default ceiling every agent
gets; `per_agent` overrides it for the agents it names — lower for a low-trust
`ci-bot`, higher for a batch job. On top of that, `per_upstream` caps each tool
independently, so a chatty GitHub loop can't exhaust the budget an agent needs
for Slack or Linear. `per_delegation` caps **each** delegated sub-token
individually — one number, because sub-token ids are minted at runtime and
can't be named in a static policy. It is additive: a child's spend still counts
against its parent's ceiling, but a runaway child hits its own
`delegation_budget_exceeded` before it can starve the parent or its siblings.
All keys are optional.

**Per-agent approval.** `approvals.per_agent` gives a named agent its own
approval friction on top of the shared grants. For each listed action glob, an
otherwise-allowed request by that agent is clamped to `require_approval` — a
human still has to say yes each time (it never reuses a remembered approval).
It only ever *adds* friction: it cannot widen a grant or soften an explicit
`deny`, and a closed `schedule` still wins. It is the read of "this low-trust
agent may do everything the policy allows, but I want a nod before it merges or
deletes," without forking a whole separate policy for that one agent. A
delegated sub-token inherits its root agent's overlay, so a fresh delegation is
not an escape hatch. A rule may be **target-scoped** — `{ action, targets: [...] }`
instead of a bare string — so the nod is required only where the target matches
(e.g. `pr:merge` on `/repos/acme/prod-*` but not on scratch repos); a bare string
means any target. An MCP batch, whose target can't be pinned per-member, always
triggers a scoped rule (fail-closed — the worst case is one extra approval, never
a bypass). Pre-action permissioning, not an audit record.

**Weighted budgets.** By default every action costs 1, so a `repo:read` and a
`repo:delete` drain the ceiling equally. `budget.weights` maps action globs to a
cost so the dangerous few spend more of the *same* ceilings:

```yaml
budget:
  max_actions_per_hour: 200
  weights:
    "repo:delete": 25   # a delete spends 25 of the 200
    "pr:merge": 10
    "pr:*": 5           # any other pr action spends 5
```

An action's cost is the **highest** matching weight (so a broad cheap glob can't
under-charge a risky action); unlisted actions cost 1. Weights are positive
integers ≥ 1 — they tax the risky few rather than discount the common many, so
to make reads *relatively* cheaper, scale everything up (e.g. ceiling 2000,
read 1, merge 100). Every ceiling above now measures cost units per hour. See
the cost of any action with `grenz explain`, and `grenz policy lint` flags the
common mistakes — a weight above a ceiling (the action can never forward — use
`deny`), a dead carve-out shadowed by a broader higher weight, and a glob that
taxes more than one tool. Two notes: budgets still enforce under `--shadow`
(a weights rollout tested in shadow mode will see real `429`s), and because past
log rows keep the cost they were billed at, a freshly added weight only fully
takes effect after the rolling hour rolls over.

Rules can also be **target-scoped**: write a rule as `{action, targets}` and
it matches only when a target glob matches what the request touches (the
GitHub URL path, the MCP call label). A scoped allow that misses its target
falls through to deny-by-default; a scoped deny fires only where it names.
Globs work like action globs (`*` crosses `/`). An MCP JSON-RPC **batch** is
evaluated message by message — each carries its own target, so a scoped rule
fires on a batched call exactly as it would on the same call sent alone.
Batching is never a way around a scope. Test any rule with
`grenz explain github pr:create /repos/acme/x`.

Validate any time with `grenz policy check`. Ready-to-copy packs live in
[`proxy/examples/policies`](proxy/examples/policies).

### Linting and simulating changes

`grenz policy lint` runs static checks over the active policy: a pattern
that matches no known action for its upstream type (a likely typo, most
dangerous on a `deny`), a pattern fully shadowed by an earlier one in the
same clause (redundant), and any `allow`/`require_approval` pattern that
fans out to three or more concrete actions (worth double-checking it grants
only what you intend). Findings are warnings, not errors — safe to run in CI.

```bash
grenz policy lint
```

Before shipping a policy change, replay it against real traffic:

```bash
grenz policy diff new-policy.yaml
#   lint (candidate): ...
#   replay against history:
#     github:pr:merge  allow -> deny  (3 historical occurrences)
```

This lints the candidate file the same way, then re-evaluates every distinct
`(tool, action)` pair seen in the local request log against both the active
and candidate policy, showing only the pairs whose decision would actually
change. `--hours <n>` narrows the replay window (default: full history).

### Testing a policy — `grenz policy test`

`diff` shows what *changed*; `test` pins what must *stay true*. Write the
decisions you care about and run them through the real engine:

```yaml
# ~/.grenz/policy.test.yaml
tests:
  - tool: github
    action: pr:merge
    expect: deny
  - tool: github
    action: pr:create
    target: /repos/acme/x/pulls    # omit to test worst-case reachability
    expect: allow
  - tool: github
    action: issue:update
    expect: require_approval
    reason: approval_required      # optional: pin the exact reason code
```

```bash
grenz policy test                                    # active policy vs ~/.grenz/policy.test.yaml
grenz policy test tests.yaml --policy candidate.yaml  # a candidate before you ship it
```

Each case runs through the same `evaluate()` the proxy uses, so a green suite
means the policy really behaves that way. Exit code is non-zero if any case
fails **or the file asserts nothing** — drop it into CI or a pre-commit hook.
Omitting `target` tests reachability (a target-scoped allow counts as allowed);
pass a target to test enforcement on it. `reason` is optional and pins the
exact structured code.

### Drafting policy from plain English

`grenz suggest` calls an LLM to draft a candidate policy from an intent
you describe, grounded in the real action vocabulary each configured
upstream can produce — it can't invent an action that doesn't exist. The
result is never applied automatically.

```bash
printf %s "$ANTHROPIC_API_KEY" | grenz vault set llm_api_key   # once
grenz suggest "let the linear agent triage tickets but never delete"
#   Wrote .grenz/policy.suggested.yaml
#   Review exactly what it would change:
#       grenz policy diff .grenz/policy.suggested.yaml
```

Every response is validated through the exact same strict schema every
hand-written policy goes through before anything is written to disk — an
invalid response is rejected outright, not silently patched up. Review the
draft with `grenz policy diff` (which lints it and shows what it would
actually change against your live traffic) before ever copying it over the
real `policy.yaml` yourself.

### Shadow mode — try a policy before enforcing it

`grenz run --shadow` runs the proxy **non-enforcing for policy decisions
only**. A request the policy would deny or send to approval is forwarded
anyway and logged as a *would-block*, so you can watch what a candidate
policy would do against real traffic, then enforce it by dropping the flag.

```bash
grenz run --shadow
#   ⚠ SHADOW MODE — policy denials are NOT enforced.
#   [shadow] would-deny claude-code github:pr:merge -> 200 (explicit_deny)
```

Every credential-protecting gate stays fully enforced even in shadow mode:
a bad or revoked token, a delegation-scope violation, a secret caught by DLP,
the budget cap, and any vault failure all still block. Shadow only suppresses
the policy verdict itself. The would-block tally shows up in the local
console summary; nothing new leaves the proxy.

### Live-reloading policy

`grenz run --watch` recompiles `policy.yaml` whenever it changes and swaps the
live policy in place — no restart, and in-flight approvals are preserved. A
policy that doesn't compile is rejected and the running one stays active, so a
typo can't take your proxy down.

```bash
grenz run --watch
#   policy watch: on
#   [policy] reloaded (4 grants, was 3)
#   [policy] reload REJECTED: malformed policy at `grants.1`: ... — keeping current
```

This closes the authoring loop: draft with `grenz suggest`, preview with
`grenz policy diff`, try it non-enforcing with `--shadow`, then edit and watch
it apply live. (When policy is pulled from a team plane via `policy_source`,
`--watch` is a no-op — the plane is authoritative.)

### Policy history and rollback

Every time the proxy adopts a policy — at `grenz run` startup and on each
`--watch` reload — it saves the `policy.yaml` it loaded into a local
`.grenz/policy-history/` directory. List past versions and revert a bad edit:

```bash
grenz policy history
#   3  20260715T140200Z  a1b2c3d4  412B  (current)
#   2  20260715T112000Z  9d8c7b6a  380B
#   1  20260714T091000Z  3f2a1b0c  356B

grenz policy rollback 2          # dry run: shows which decisions would change
grenz policy rollback 2 --yes    # restores snapshot 2 (snapshotting the current
                                  # file first, so a rollback is itself reversible)
```

These snapshots are plain, individually deletable files for operator
convenience — not an audit trail and not tamper-evident. Rollback refuses a
snapshot that no longer compiles, and the whole directory is safe to delete.

### Tools & actions

Grenz maps each wire request to a normalized `resource:verb` action, then
matches it against the policy (patterns support `*` and `?`). Each upstream has a
`type` that selects an adapter:

| `type` | Transport | Example request | Action |
|---|---|---|---|
| `github` | REST | `PUT /repos/o/r/pulls/1/merge` | `pr:merge` |
| `mcp` | MCP (JSON-RPC) | `tools/call` name=`create_issue` | `call:create_issue` |
| `linear` | MCP | `tools/call` name=`save_issue` | `issue:write` |
| `slack` | MCP | `tools/call` name=`post_message` | `message:send` |

`github` classifies REST paths; `mcp` matches raw tool names; `linear` and
`slack` normalize their servers' actual tool names into a canonical taxonomy so
policies read in domain terms (Linear uses `save_*` upserts → `:write`). Unmapped
calls fall back to `call:<name>`, which a deny-by-default policy still blocks.
Adapters are the seed of Grenz's "policy graph" —
[add one](proxy/src/adapters) without touching call sites.

> **Wildcards are broad.** On a semantic adapter, `allow: ["issue:*"]` grants
> reads *and* writes. Prefer enumerating access levels (`issue:read`,
> `issue:write`) so an allow grants exactly what you mean.

## Wrapping an MCP server (Linear, Slack, anything)

Add an upstream to `grenz.yaml` and a matching grant to `policy.yaml`:

```yaml
# grenz.yaml
upstreams:
  linear:
    type: linear                       # or: mcp | slack | github
    base_url: https://mcp.linear.app/sse
    credential: linear_token
```

```yaml
# policy.yaml — grants:
  - tool: linear
    allow: ["session:*", tools:list, issue:read, comment:read]
    require_approval: [issue:write] # save_issue creates or updates an issue
    deny: [comment:delete, attachment:delete]
```

Then `printf %s "$LINEAR_TOKEN" | grenz vault set linear_token` and point your
MCP client at `http://127.0.0.1:8787/u/linear`.

## Approvals

Actions under `require_approval` **block** while Grenz waits for a human — held
open until someone decides, or the TTL (default 5 min) expires, which is a DENY.

> **Practical ceiling: 255 seconds.** Bun caps a held connection at 255s, so an
> approval not decided within that window drops the agent's connection and is
> abandoned rather than answered — the agent must retry to get a fresh prompt.
> A `ttl_seconds` above 255 is accepted but cannot be reached in full; `grenz
> run` warns at startup when you set one. Set `ttl_seconds: 240` or lower if you
> need the TTL itself to be what decides the outcome.

If the requesting agent disconnects while its approval is still pending, Grenz
**cancels** that approval — the pending prompt goes stale and a later
`grenz approve <id>` reports it as not found. This closes the "approved into the
void" gap: an action is never performed for a requester that has already left.

```bash
grenz approvals            # list what's waiting
grenz approve <id>         # let it through
grenz deny <id>            # block it
```

A `require_approval` rule can carry a `message` — an operator note shown to the
human approver (in `grenz approvals`, the console, and the Slack prompt) so they
know what to check before deciding:

```yaml
    require_approval:
      - action: issue:update
        message: "Confirm the change is on a tracked ticket before approving."
```

Like a deny `message`, it is static policy text (never request data), so it is
log-safe; it lives only on the pending approval and is never written to the log.

Optionally push a Slack notification when an approval is pending (the webhook URL
is a secret, kept in the vault, never logged):

```bash
printf %s "$SLACK_WEBHOOK_URL" | grenz vault set slack_webhook
```

When a webhook is configured, Grenz also posts a short follow-up when the
approval settles — approved, denied, expired, or **withdrawn** (the requester
disconnected before deciding) — so the prompt is visibly closed and nobody acts
on a dead request.

### Dual-control (quorum, optional)

For the highest-stakes actions you can require **N distinct approvers** before
the action proceeds — separation of duties. Add a `quorum` map (action glob →
required approvers, 2–16); unlisted actions need 1, exactly as today.

```yaml
quorum:
  "repo:delete": 2
  "*:delete": 2       # any delete needs two
```

A quorum action stays blocked until N *different* people approve; a single
**deny** vetoes it immediately, and the one TTL covers the whole window
(not all N in time → deny). A quorum prompt is **always fresh** — a single
remembered "yes" can never bypass dual-control (a remembered *deny* still
stands). Approvers identify themselves with `--as`:

```bash
grenz approve <id> --as alice     # 1/2 — recorded, waiting for one more
grenz approve <id> --as bob       # 2/2 — approved, the action proceeds
```

> **Trust model — read this.** The approver id is a **self-asserted label**
> (defaulting to `$GRENZ_APPROVER`, then your OS user). Quorum is separation of
> duties **by cooperation** — it requires two approval actions under two names —
> **not** cryptographic proof of two distinct humans. The loopback admin API and
> its token remain the security boundary: anyone who can reach it can approve
> under any name. Use quorum to prevent *mistakes* and enforce a two-person
> convention, not to defend against a determined insider. (Server-derived
> identity via named admin tokens is a planned upgrade.)

### Remembering decisions (optional)

Repeated prompts for the same action train humans to rubber-stamp. With
`remember_seconds`, a human's approve **or deny** for the exact
`(agent, tool, action, target)` is reused for a short window instead of
re-prompting — a retry of the same merge doesn't ask twice, and a denied
action stays denied instead of prompting until someone slips.

```yaml
approvals:
  ttl_seconds: 300
  remember_seconds: 120   # 0 = off (default)
```

Scope is exact: approving a merge on PR #1 never approves PR #2. Prompts
caused by dynamic context — a DLP finding in the body, or a risk step-up —
always ask a human, every time. Remembered decisions are held in memory only
(a restart or a `--watch` policy reload clears them) and show up in the local
log under their own reason codes (`approval_remembered_grant` /
`approval_remembered_deny`), so you can always tell a reused decision from a
fresh one.

## Content scanning (DLP)

A *permitted* action can still carry a bad payload — a secret pasted into a
`pr:comment`, or credentials POSTed to an allowed host. Turn on outbound body
scanning and Grenz blocks (or holds for approval) requests whose body contains a
credential shape (AWS/GitHub/Slack/Stripe keys, private-key blocks, `secret=…`
assignments). Only the **detector name** is ever logged — never the matched value.

```yaml
# policy.yaml
dlp:
  scan_bodies: true
  on_match: deny        # deny | require_approval
```

## Scan for exposed credentials — `grenz scan`

Most agent setups scatter long-lived credentials in plaintext config files —
`.env`, `mcp.json`, `.claude.json` — and today's infostealers target exactly
those files. `grenz scan` shows you what an infostealer would harvest right now,
then funnels each secret into the vault so the file holds only a revocable token.

```console
$ grenz scan
grenz scan — 2 plaintext credential(s) an infostealer would take right now,
across 1 of 4 file(s) checked:

  ./.env
    · aws_access_key ×1
    · github_token ×1

These sit in plaintext — off-box that's a straight credential harvest.
Move each behind the vault so the file holds only a revocable token:
  grenz protect                                # vault your upstream token + safe-defaults
  printf %s "$SECRET" | grenz vault set <key>  # any other secret
```

It reuses the same detectors as DLP — only the **detector name and a count** are
ever printed, never the matched value — reads a curated list of config surfaces
(pass extra paths as arguments), and **exits non-zero if anything is found**, so
it drops straight into CI or a pre-commit hook as a "no plaintext credentials"
guard. Read-only and offline.

## Risk (a first "SOC" signal)

A spike in denials is your earliest sign of a compromised or prompt-injected
agent. `grenz risk` scores each agent from the local log, and `grenz run` emits
a `[risk]` alert when an agent crosses into elevated/high.

```bash
grenz risk            # e.g. claude-code [high] score 67 — 8 denials, 89% deny rate
```

Risk scoring can also act, not just alert: add an opt-in `step_up:` block to
`policy.yaml` and a `high`-risk agent's next otherwise-auto-allowed action is
upgraded to `require_approval` instead of going straight through — a human is
pulled in without cutting the agent off entirely. It composes with everything
above: the approval shows up in `grenz approvals`/the console exactly like
any other pending approval, tagged `[risk:high]` so you can see why.

```yaml
# policy.yaml
step_up:
  window_seconds: 900   # optional, default 900 (15 min) — same window `grenz risk` uses
```

## First use of a capability — `first_use`

Risk watches for *denial spikes*; `first_use` watches for an agent's *first-ever*
use of a capability. A hijacked agent typically reaches for something it has
never done — the read-only bot that suddenly tries `pr:merge`. Add an opt-in
`first_use` block and the **first** time an agent forwards a gated
`(tool, action)`, the otherwise-allowed action pauses for a human (or is
denied). Let it through once and it flows normally thereafter.

```yaml
# policy.yaml
first_use:
  on_first: require_approval          # require_approval (default) | deny
  only: ["*:delete", "pr:merge", "call:*"]   # REQUIRED — the actions to gate
  window_seconds: 2592000             # optional lookback; omit = your log's lifetime
```

Scope `only` to capabilities worth a human's eyes on first use — destructive
verbs and, for a generic MCP server, `call:*` (so the gate fires on the first
call of a never-used tool). **Don't** gate session/handshake plumbing
(`session:*`, `tools:list`): a fresh agent would stall behind approvals. `only`
is required for exactly this reason.

The approval shows up in `grenz approvals`/the console tagged `[first_use]` and
always asks fresh (never a remembered decision). Approving unlocks that
`(tool, action)` for **all targets** until the window lapses — the prompt says so,
so you know what a Yes covers. `first_use` only ever tightens: it never overrides
an `explicit_deny`, skips actions outside `only`, and skips an action a human has
already decided on for this request — one an operator just allowed with `grenz
grant`, or one covered by an open `break-glass` window. It applies on top of any
*other* clamp, so `on_first: deny` still hard-denies a novel action that a closed
schedule or a `require_approval` rule had already turned into a prompt — a
first-use deny is never downgraded to a question. A denied first attempt does not
whitelist itself. Batches are inspected per member, so a novel action can't ride
inside an MCP batch. Check whether an action would trip it with `grenz explain`.

This is a **behavioral novelty gate**, not a log of past activity. It reads the
local request history only to answer the pre-action question "has this capability
been forwarded through this proxy recently enough to be routine?", exactly as
budgets read it to count recent actions. The memory is deliberately forgetful —
it lives only in the truncatable local log and never leaves the proxy; if the log
is truncated, Grenz simply asks again. Because write access to that log is a
decision input, run the proxy so only it can write its data directory.

> **Rollout note:** a policy that uses `first_use` is rejected by an older proxy
> that doesn't know the key (a malformed policy fails closed). Upgrade proxies
> before distributing a policy with this block.

## Time-boxing an agent — `schedule`

Grenz gates *what* an agent may do and *how much*; `schedule` gates *when*.
Confine a CI deployer to business hours, or a batch agent to a maintenance
window. Outside every open window, any action that would otherwise be permitted
is clamped to `on_closed` — deny-by-default is only ever tightened, never
loosened.

```yaml
# policy.yaml
schedule:
  timezone: America/New_York     # IANA name; default UTC
  windows:
    - days: [mon, tue, wed, thu, fri]
      start: "09:00"             # HH:MM, 24-hour; start inclusive
      end:   "17:00"             # end exclusive; must be after start
  on_closed: deny                # or require_approval (a human can still authorize off-hours)
```

Windows are matched in `timezone`, so daylight saving is handled for you.
A single window can't cross midnight — express an overnight shift as two
windows (`22:00`–`23:59` and `00:00`–`06:00`). Outside hours, a denied request
reports `schedule_closed` (403); `on_closed: require_approval` routes through
the normal approval flow instead, tagged `[schedule:closed]` and always fresh
(never a remembered decision). The schedule never overrides an `explicit_deny` —
a forbidden action stays forbidden with its own reason. Check the current state
any time with `grenz explain`.

## Kill-switch

Risk tells you an agent looks compromised; the kill-switch is how you respond.
`grenz revoke <agent>` cuts it off **immediately** — the running proxy denies
its every request from that moment, before any upstream call, policy check, or
credential fetch. It takes effect **mid-flight, no restart**: the command talks
to the running proxy over its loopback admin API.

```bash
grenz revoke claude-code --reason "risk:high denial spike"
grenz revocations                 # list who's cut off
grenz restore claude-code         # lift it
```

The revocation is persisted to `revocations.json` in the Grenz home, so it
survives a restart. If the proxy isn't running when you revoke, the command
writes that file directly and the cut-off applies on the next `grenz run`. A
corrupt revocation file makes `grenz run` **refuse to start** rather than serve
with an unknown kill-list — fail closed, like a malformed policy.

**Rotating a token.** `grenz rotate <agent>` issues a fresh `GRENZ_TOKEN`,
rewrites that agent's stored hash in `grenz.yaml` (comments preserved), and
prints the new token once. It takes effect on the next `grenz run`. The full
leak response is `grenz revoke <agent>` (cuts the old token off immediately,
in memory) → `grenz rotate <agent>` (new token) → `grenz restore <agent>`
(lift the revocation) → restart.

**Token expiry.** Delegations and admin tokens already expire; a primary
agent's `GRENZ_TOKEN` never did — a leaked one was a permanent identity until
someone rotated it. Give an agent an optional `expires_at` to bound that window:

```yaml
agents:
  - id: claude-code
    token_hash: "ab12…"
    expires_at: 2026-08-01T00:00:00Z   # RFC 3339, time zone REQUIRED
```

Past that instant the token is no identity — the agent gets the same plain
`401 invalid_token` an unknown token gets (the wire never says "expired": that
would only tip off a thief, who can't self-rotate anyway). You see the truth on
your side: an `agent_token_expired` row in the request log, a ✗ in `grenz
doctor`, and a startup line from `grenz run` for anything expired or lapsing
within the week. Re-mint with `grenz rotate <agent>` (edit or lift `expires_at`
first, or the new token is born expired — rotate warns you if so). Absent
`expires_at`, nothing changes: tokens live forever as before. A zone-less or
malformed value is rejected at load (fail closed). One fleet grenz: a binary
old enough to predate this field refuses to start against a config that sets it
— roll the binaries forward before the config.

## Agent scope — confine a standing agent

Every agent shares one policy, so a broad `repo:read`/`pr:create`
grant lets *any* agent do it on *any* repo — the shared policy can't say "*this*
agent, only *these* repos, only *these* actions." Confine a standing agent on two
axes right on its config — which **targets** it may reach and which **actions** it
may take:

```yaml
agents:
  - id: reviewer-acme            # a Claude Code instance that reviews one org
    token_hash: "ab12…"
    actions: ["repo:read", "pr:read"]  # read-only — no writes, ever
    targets: ["/repos/acme/*"]         # and only within acme/
```

A request outside either list is denied — `agent_action_scope` for an action not
in `actions`, `agent_target_scope` for a target not in `targets` — **even when the
shared policy allows it.** So a token scoped this way can't be tricked (or
compromised) into `pr:merge`, or into reading `orgB/secret`: the agent's own
ceiling gates first. Either axis is optional and independent; omit one to leave
that axis unrestricted, omit both for a plain agent. Both are matched by the same
glob engine as rule and delegation scope.

This scope is also the **root of every delegation** the agent mints: a sub-token
attenuates *from* its agent's reach and can never exceed it, on either axis — so
`grenz delegate reviewer-acme --actions pr:merge` grants nothing (the agent itself
can't merge), and `--targets "/repos/*"` still only ever reaches `acme/`.

You don't have to hand-edit YAML to get there. With `grenz run` up, mint a scoped
agent in one line — it's persisted to grenz.yaml and authenticates immediately,
no restart:

```bash
grenz agent create reviewer-acme --actions "repo:read,pr:read" --targets "/repos/acme/*"
#   → prints a GRENZ_TOKEN once; a read-only agent that can reach nothing outside acme/
```

Omit `--actions`/`--targets` for an unrestricted agent. Widen or tighten either
axis later by editing that agent's `actions:`/`targets:` list.

## Per-agent policy profiles — different grants for different agents

Agent scope (above) confines *which* targets/actions an agent's token can
reach at all. `policy_profiles` goes further: give an agent its **own**
`allow`/`deny`/`require_approval` rules instead of every agent sharing the one
default `policy.yaml`. Declare named profiles at the top level of `grenz.yaml`,
each pointing at a local policy file, and reference one by name on an agent:

```yaml
# grenz.yaml
policy_profiles:
  ci-merge:   { file: profiles/ci.yaml }
  triage:     { file: profiles/triage.yaml }
agents:
  - id: ci
    token_hash: "..."
    policy: ci-merge
  - id: bot
    token_hash: "..."
    policy: triage
  - id: legacy          # no policy → shared default
    token_hash: "..."
```

Each profile file (`profiles/ci.yaml` above) is written as a normal policy
YAML — but **only its `grants` are used.** Every protective construct —
`tripwires`, `dlp`, `step_up`, `budget`, `schedule`, `first_use`, `pins`,
`responses`, `quorum` — is always inherited from the default `policy.yaml` and
**cannot be weakened by a profile**, even if the profile file sets one. A
profile that omits `tripwires:` does not disable the fleet-wide tripwires for
that agent; it physically cannot change them. The only thing a profile
changes is *which tools an agent may call, and how* (allow / deny /
require_approval).

An agent with no `policy` field falls back to the shared default —
byte-for-byte today's behavior. Profile names must match
`^[a-z0-9][a-z0-9_-]{0,63}$`. An agent whose `policy` names a profile that
isn't declared in `policy_profiles` (or a profile file that fails to compile)
is a config error: `grenz run` refuses to start, the same as a malformed
policy today. **Decoy agents may not set `policy`** — a decoy is tripped and
revoked before any policy would be selected, so a profile on one would be
silently inert; the config rejects it instead.

**`file` is a local path — never a URL.** `policy_profiles.*.file` is resolved
against the Grenz home. To distribute profiles fleet-wide instead, drop `file`
entirely: a **name-only** declaration (`ci: {}`, or a bare `ci:`) declares that
the profile exists without pinning it to a local file, and its content arrives
over the signed bundle (`policy_source`) — see [Sign the policy you ship to a
fleet](docs/quickstart.md#sign-the-policy-you-ship-to-a-fleet-grenz-policy-sign)
for `grenz policy sign --profile`. A name declared this way but not carried by
the bundle (including a proxy running without `policy_source` at all) resolves
to nothing: any agent referencing it denies `agent_policy_unresolved` on every
request rather than quietly falling back to the shared default.

> **Limitation — read this before you edit a profile.** `grenz run --watch`
> hot-reloads only the default `policy.yaml`. Profile files are compiled once
> at startup: **editing a profile file has no effect on a running proxy until
> you restart `grenz run`.** Tightening a profile and expecting it to take
> hold live is a silent no-op today — if you need it to apply now, restart.

## Socket mode (opt-in)

Expiry bounds a leaked token in *time*. Socket mode bounds it in *reach*: set
`listen.socket` and agent traffic moves onto a unix domain socket, while the
admin plane stays on TCP loopback.

```yaml
listen:
  socket: run/agent.sock   # relative paths resolve against the Grenz home
  host: 127.0.0.1          # admin listener (console, metrics, healthz)
  port: 8787
```

```bash
curl --unix-socket ~/.grenz/run/agent.sock http://localhost/u/github/repos/o/r
```

**What this actually buys you — and what it doesn't.** The honest claim is
*the agent listener is reachable only by your own OS user.* Same-user processes
are inside the boundary: your own shell, and anything else running as you. This
narrows **who can reach** the agent listener; it does not authenticate **which
process** is the agent. What it removes is reach from outside your uid:

- **Other users** on a shared box or CI runner.
- **Containers.** On Docker Desktop any container can reach a host process bound
  to `127.0.0.1:8787` through `host.docker.internal` — binding to loopback does
  not stop it. A unix socket does, by construction.
- **Browser-origin probes** (DNS rebinding, localhost CSRF) drop to zero,
  including the unauthenticated `/healthz` fingerprint.

Agent routes on the TCP listener answer `403 wrong_listener`. If the token was a
real one, Grenz logs it with the agent id and notifies you once — a valid token
arriving on the wrong door is either a misconfigured agent or a stolen token
being replayed. It is never auto-revoked, so a misconfigured agent of your own
can't self-destruct.

**Compatibility — read before switching.** This is opt-in because the clients
Grenz wraps are poor unix-socket citizens. MCP-over-URL clients generally take a
URL and cannot speak unix sockets at all, so they can't join socket mode; `curl`
needs `--unix-socket`; and the socket is unreachable from Docker Desktop
containers (which is the point, but it does mean a containerized agent stays on
TCP). The console, `/metrics`, and every `grenz` admin command are unaffected —
they live on the TCP admin listener.

Two operational notes. The socket's parent directory is created `0700` and that
is what enforces the boundary — if it already exists with group or other access,
Grenz refuses to start rather than silently tightening a directory you
configured. And only one proxy may own a socket path: a second `grenz run`
against the same path exits instead of taking it over, which is what keeps
`grenz revoke` reaching the proxy that is actually serving your agents. That
holds atomically — the listener is bound to a private staging name and then
published with `link(2)`, which fails if anything already holds the path — so
two proxies racing to start cannot both end up serving. (Do not rely on
`bind()` for this: unlike TCP, `Bun.serve({ unix })` on an occupied path
succeeds and takes the path over.) Because the staging name needs room inside
the platform's `sun_path` limit, the resolved socket path is capped at 91
bytes; `grenz doctor` and startup both reject a longer one with remediation
text. Same fleet grenz as `expires_at`: an older binary rejects a config that
sets `listen.socket`, so roll binaries forward before the config.

## Keeping it running — `grenz service`

`grenz run` is a foreground process: close the terminal or reboot and the whole
agent fleet loses its firewall. Grenz is deliberately not its own daemon — it
hands supervision to the platform's own, **user-scoped so no root is needed**:
launchd on macOS, `systemd --user` on Linux.

```bash
grenz service install     # write the unit + start it (restarts on crash, comes back at login)
grenz service status      # is it loaded / running?
grenz service uninstall   # stop it and remove the unit
grenz service print       # just show the unit + activation command (writes nothing)
```

`install` points the unit at the current binary and this home, so it runs exactly
the `grenz run` you would have. Running more than one proxy on a machine? Give each
a `--name` (`grenz service install --name ci`) — the label and unit file are
distinct per name, so homes don't collide. `--home` selects which home the service
runs against. On an unsupported OS (or to place the unit yourself), `grenz service
print` emits the unit and the one command that activates it.

## Decoys (honeytokens)

Plant bait no legitimate workload ever touches, and catch a leaked token or a
probing agent on the **first touch**:

```bash
grenz decoy token honeypot-ci        # prints a decoy GRENZ_TOKEN, once
grenz decoy upstream billing-admin   # a decoy upstream no policy grants
grenz decoy list                     # what's planted, and what has tripped
grenz run
```

A decoy token is byte-indistinguishable from a real one, but no real agent
holds it. A decoy upstream carries no credential — it is unforwardable by
construction (the config won't even load if you try to give a decoy a
credential). Any request that presents the decoy token, or touches the decoy
upstream, is high-confidence compromise: Grenz revokes the toucher in the same
request (its every later request is cut off by the kill-switch), pings your
operator channel, and returns the toucher the same generic response an innocent
mistake would get — a plain `401` for a bad token, a plain `403` for an
ungranted upstream. It learns it is cut off, never that it stepped on a trap.

A trip is an ordinary revocation: you see it in `grenz decoy list` and `grenz
revocations`, and `grenz restore` re-arms the decoy. `grenz policy lint` flags
any policy grant that names a decoy upstream — no legitimate policy grants one.

**Scope.** Grenz sees only `GRENZ_TOKEN` traffic addressed to this proxy.
Decoys do not detect token theft itself, use of real upstream credentials stolen
elsewhere, or an attacker who never replays through Grenz. The claim is
precise: any request through Grenz that presents a decoy token or touches a
decoy upstream is high-confidence compromise of whatever held it — and the
toucher is cut off in the same request.

## Delegation (agents spawning agents, safely)

Your agent spawns helpers — a reviewer, a test-runner, a doc-writer. Without
delegation they'd all share the one token, i.e. the *full* scope. Grenz lets a
parent mint a short-lived **child token carrying a strict subset** of its own
powers — no new human, no policy edit, no cloud round-trip.

The agent mints one itself over the proxy (using its own `GRENZ_TOKEN`):

```bash
curl -X POST -H "Authorization: Bearer $GRENZ_TOKEN" \
     -d '{"actions":["repo:read"],"targets":["/repos/acme/*"],"ttl_seconds":600,"note":"reviewer"}' \
     http://127.0.0.1:8787/delegate
#   → { "token": "wdl_…", "delegation_id": "del_…", "expires_at": … }
```

…or you mint one from the terminal for a configured agent:

```bash
grenz delegate claude-code --actions repo:read,pr:read --ttl 600 --note reviewer

# scope it to WHICH targets, too — this child can read only repos under acme/:
grenz delegate claude-code --actions repo:read --targets "/repos/acme/*" --ttl 600

grenz delegations          # list live children, their scope, and expiry
```

The guarantee is **attenuation-only**, macaroon-style: a child's scope is the
**intersection** of what its parent's live policy allows *and* what was
delegated — on **both** axes, actions *and* targets. Ask for `pr:merge` in a
delegation whose parent can't merge, and the child still can't — the request is
clamped at use (`explicit_deny`). Reach for an action outside the delegated set
and it's denied (`delegation_scope`); reach a target outside `--targets` and it's
denied (`delegation_target_scope`) even when the action itself is allowed — this
is what stops a child scoped to one repo from touching another. A child **can**
re-delegate, narrowing further; the chain is capped at 5 hops and every hop must
match, so a widened descendant grants nothing.

Delegations are **time-boxed** (default 15 min, max 1 hour) and compose with the
kill-switch: revoke a `delegation_id` to cut one child, or revoke the **parent
agent to cascade** — every child it spawned dies at once. Removing the parent
from `grenz.yaml`, or letting its `expires_at` lapse, has the same effect: a
sub-token is only ever a narrowing of its root, so with no root to narrow from it
stops resolving (`401`). The child token is shown once and never logged; only its
hash is stored.
Set `budget.per_delegation` to cap each child's hourly spend individually;
per-token usage shows as `spent` in `grenz delegations` and
`/console/delegations`.

## Just-in-time grants

Delegation spawns a new, narrower sub-token. Sometimes what you actually want
is simpler: *this* agent, using its *own* existing `GRENZ_TOKEN`, temporarily
allowed to do one more thing — "let the on-call agent merge without approval
for the next hour while it ships this hotfix." That's a JIT grant: no new
token, no restart, auto-expiring back to the static policy.

```bash
grenz grant claude-code --actions pr:merge --ttl 3600 --reason "hotfix"
grenz grants                        # list what's currently widened
```

A grant can widen a gap in policy (`no_matching_allow`) or skip a
per-request `require_approval` check for its TTL — minting the grant *is*
the human decision. It can **never** override an explicit `deny`; that stays
the policy author's hard line, movable only by editing `policy.yaml` itself.
A JIT-granted allow is still subject to risk-adaptive step-up: if the agent
is separately behaving suspiciously, a human still gets pulled in despite
the grant.

Cut a grant short with the same kill-switch used everywhere else:

```bash
grenz revoke grant_...
```

## Blast radius

Policy grants are globs — `repo:*` reads clearly but doesn't say what it
*means*. `grenz blast-radius` answers "if this agent's GRENZ_TOKEN leaks
right now, what can actually be done with it?" by expanding every grant
against each adapter's known action vocabulary, and listing every live
delegated sub-token that already exists.

```bash
grenz blast-radius            # defaults to the policy's agent
```

For each upstream it reports which concrete actions are auto-allowed,
which require approval, and flags any single grant that fans out to three
or more actions (e.g. `repo:*` → `repo:read, repo:write, repo:delete`) so an
over-broad grant doesn't hide in plain sight. Upstreams typed `mcp` (arbitrary
tool names) can't be enumerated and are shown as raw patterns instead. This is
a snapshot of what current policy permits, recomputed fresh each run — not a
history of what happened.

## Why was that denied? — `grenz explain`

With policy, JIT grants, risk step-up, budgets, and the kill-switch all in
play, "why did that happen?" deserves a one-command answer. `explain` traces a
`(tool, action)` through the same layers the proxy applies, in the same order,
using the same code — offline, read-only:

```bash
grenz explain github pr:merge
#   verdict now:  DENY (explicit_deny)
#   policy:       deny (explicit_deny) — matched deny "pr:merge"
#   kill-switch:  not revoked
#   jit grant:    grx "pr:*" — matches, but a grant never overrides an explicit deny
#   budget:       agent 37/100 this hour
#                 github 12/50 this hour
#   step-up:      configured (15m window), current risk low
#   note:         DLP (body) and egress (URL) checks depend on the concrete request
```

`--agent <id>` explains for a specific agent (default: the policy's agent).

## Live console

A minimal local dashboard — requests, allow/deny/approval counts, one-click
approve/deny, shadow would-block tallies, per-agent and per-upstream budget
usage, live risk badges, and active grants/delegations — lives in
[`console/`](console). It reads the proxy's loopback admin API server-side;
the admin token never reaches the browser.

```bash
grenz run                                 # one terminal
cd console && bun install && bun run dev   # → http://localhost:4180
```

`grenz status` prints the same summary from the terminal.

The admin API also answers **`GET /console/explain?agent=&tool=&action=&target=`**
— the same verdict `grenz explain` gives, but computed against the *running*
proxy's live state (live budget spend, active JIT grants, kill-switch,
hot-reloaded policy). It's admin-gated and returns decision metadata only (no
request bodies, no credentials), so the console — or a quick `curl` — can ask
"why would this action be allowed or denied right now?" without touching the CLI
or the on-disk snapshot.

## Checking your setup

`grenz doctor` runs offline preflight checks against your Grenz home and
prints a `✓`/`⚠`/`✗` line per check — config and policy compile, the vault
decrypts, every upstream's credential is set, no grant points at a
non-existent upstream, and the listen port is free. It makes no network
calls. A hard problem exits non-zero, so you can gate startup:

```bash
grenz doctor && grenz run
#   ✓ config        grenz.yaml loads and validates
#   ✓ vault         identity present, vault decrypts
#   ✗ credentials   github: vault key 'github_token' missing or empty
#   1 problem(s), 0 warning(s) — fix the ✗ lines before grenz run
```

## CLI

| Command | What it does |
|---|---|
| `grenz init` | Scaffold identity, vault, admin token, config, policy; mint a GRENZ_TOKEN |
| `grenz doctor` | Offline preflight checks (config, vault, credentials, policy); exit 1 on problems |
| `grenz run` | Start the proxy (`--port`; `--shadow` to observe without enforcing; `--watch` to hot-reload policy) |
| `grenz service <print\|install\|uninstall\|status>` | Keep the proxy alive across reboots via launchd/systemd (`--name` for multiple, `--home` to target) |
| `grenz vault set <key>` / `list` | Store a credential (from stdin) / list key names |
| `grenz connect <url>` | Point this proxy at a control plane: stores the pull token and writes `policy_source` (`--public-key` to require signed bundles, `--telemetry`, `--force`) |
| `grenz policy check` | Validate + summarize the policy |
| `grenz policy lint` | Static checks: dead/shadowed patterns, overly broad grants |
| `grenz policy diff <file>` | Lint a candidate policy and replay it against historical traffic |
| `grenz policy test [file]` | Assert policy decisions through the engine (CI-friendly, exit 1 on failure) |
| `grenz suggest "<intent>"` | Draft a candidate policy from plain English (LLM-assisted, never auto-applied) |
| `grenz approvals` / `approve <id>` / `deny <id>` | List and decide pending approvals |
| `grenz revoke <agent>` / `restore <agent>` / `revocations` | Cut an agent off now (kill-switch), lift it, list |
| `grenz agent create <id>` `[--actions <a,b>] [--targets <glob,glob>]` | Mint a first-class agent live (own GRENZ_TOKEN, persisted, no restart); `--actions`/`--targets` confine its reach |
| `grenz rotate <agent>` | Issue a fresh GRENZ_TOKEN and rewrite the agent's hash in grenz.yaml |
| `grenz decoy token <name>` / `upstream <name>` / `list` / `remove <name>` | Plant a honeytoken (a decoy token or upstream); any touch revokes the toucher |
| `grenz delegate <agent> --actions <a,b>` `[--targets <glob,glob>]` / `delegations` | Mint an attenuated sub-token for a spawned sub-agent (optionally target-scoped), list live ones |
| `grenz grant <agent> --actions <a,b>` / `grants` | Temporarily widen an agent's own token (JIT), list active grants |
| `grenz risk` | Score agents by recent denial activity |
| `grenz blast-radius [agent]` | Reachable-action exposure + live delegations for an agent |
| `grenz explain <tool> <action> [target]` | Why would this be allowed/denied right now (engine + grants + step-up + budgets) |
| `grenz status` | Live decision summary |

Global: `--home <dir>` selects the Grenz home.

## Metrics

`GET /metrics` exposes Grenz's aggregate counts in Prometheus text format —
allow/deny/approval totals, the pending-approval queue depth, and how many
delegations, grants, and revocations are live. It's admin-gated (the same
`X-Grenz-Admin` token, or `Authorization: Bearer <admin-token>` so Prometheus's
`authorization` config works) and carries aggregate counts only — no agent ids,
targets, or bodies.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: grenz
    metrics_path: /metrics
    authorization:
      credentials: <admin-token from .grenz/admin.token>
    static_configs:
      - targets: ["127.0.0.1:8787"]
```

## Security model

- **Credentials never leave the proxy.** age-encrypted at rest, held in memory
  only when needed, injected only onto the outbound upstream request, never in
  logs, errors, or the agent's response.
- **Egress is pinned to the upstream origin.** The injected credential is only
  ever sent to the exact origin (scheme + host + port) of an upstream's
  `base_url`. A request whose outbound path resolves off that origin is denied
  (`egress_blocked`) before the credential is even decrypted, and upstream
  redirects are returned to the agent rather than followed — so a crafted path
  or a redirect can never carry your real credential to another host.
- **The agent holds only the `GRENZ_TOKEN`,** validated against a stored SHA-256
  hash and stripped before forwarding.
- **Fail closed.** A malformed policy or missing identity refuses to start; a
  missing credential, unknown upstream, or unmatched action denies the request.
- **The vault is pluggable** behind a `CredentialStore` interface (1Password /
  Vault / env backends slot in without touching call sites).

## What Grenz is *not*

Grenz is pre-action permissioning, by design. It is **not** post-action audit
evidence, tamper-evident logging, or compliance tooling — and it never claims to
be. The request log is plain SQLite you can truncate at will.

## Development

```bash
bun test                       # policy, adapters, vault, pipeline, approvals
cd proxy && bunx tsc --noEmit  # strict typecheck, no `any`
cd proxy && bun run build      # single-binary compile
cd console && bun run build    # build the Next.js console
```

The policy engine (`proxy/src/policy`) is pure and synchronous with table-driven
tests — every allow/deny/approval path in the spec has a case.

## Contributing

Issues and PRs welcome. The best first contributions are **tool adapters** and
**policy packs**: add an adapter in [`proxy/src/adapters`](proxy/src/adapters)
(map an upstream's wire calls to canonical actions) or a policy in
[`proxy/examples/policies`](proxy/examples/policies), with tests.

## License

[MIT](LICENSE)
