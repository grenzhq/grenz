# Quickstart: a protected MCP agent in 5 minutes

Goal: wrap an MCP server behind Grenz so your agent connects with a
`GRENZ_TOKEN` instead of the real credential, reads are auto-allowed, deletes
need your approval, and you can watch it all in a live console.

We'll use the Linear MCP server as the example; any HTTP/Streamable-MCP server
works the same way.

## 0. Build the CLI (once)

```bash
bun install
cd proxy && bun run build      # → ./proxy/dist/grenz
export PATH="$PWD/dist:$PATH"  # so `grenz` is on your PATH
cd ..
```

## 1. Initialize (30s)

```bash
export GRENZ_HOME="$HOME/.grenz"   # one home, outside your repos (recommended)
grenz init
```

This scaffolds the home (age identity, encrypted vault, admin token, config,
policy) and prints your **GRENZ_TOKEN once** — copy it.

> **Put the home outside your worktrees.** Without `GRENZ_HOME`, `grenz init`
> uses `./.grenz` — which places the vault and admin token *inside the repo your
> agent works in*, so the agent could read its own vault and recover the real
> credential. One global home (and one `grenz run`) for the whole fleet is the
> boundary; `grenz init` warns you loudly if it lands inside a git repo. Scope
> individual agents with per-agent `actions:`/`targets:` instead of separate
> homes. Keep it running across reboots with `grenz service install`.

## 2. Add the MCP upstream (1 min)

> `grenz init` already scaffolds a working **GitHub** upstream (the headline
> example) with a matching policy. If GitHub is all you need, just set its
> credential — `printf %s "$GITHUB_TOKEN" | grenz vault set github_token` — and
> skip to step 4; you can watch allow/deny with a plain `curl`, no MCP client
> required. The steps below add a *second* upstream — an MCP server — to show the
> general shape.

Edit `.grenz/grenz.yaml` and add an upstream:

```yaml
upstreams:
  linear:
    type: mcp
    base_url: https://mcp.linear.app/sse
    credential: linear_token
```

Put the real credential in the vault (read from stdin, never argv):

```bash
printf %s "$LINEAR_TOKEN" | grenz vault set linear_token
```

## 3. Write the policy (1 min)

Edit `.grenz/policy.yaml`. Deny-by-default; precedence is
deny > require_approval > allow:

```yaml
agent: claude-code
on_behalf_of: you@example.com
grants:
  - tool: linear
    allow:
      - "session:*"       # protocol handshake — required to connect
      - tools:list
      - resources:list
      - "call:list_*"      # read-only tools
      - "call:get_*"
      - call:create_issue
    require_approval:
      - "call:delete_*"    # deletes wait for you
    deny:
      - "call:*_admin"
budget:
  max_actions_per_hour: 200   # default ceiling, per agent
  per_upstream:               # optional: cap individual tools too
    github: 100               # github alone can't exceed 100/hour...
    linear: 20                # ...even if the default 200 has headroom
  per_agent:                  # optional: give an agent its own ceiling
    ci-bot: 20                # ci-bot gets 20/hour instead of 200
  weights:                    # optional: risky actions cost more of the ceiling
    "repo:delete": 25         # one delete spends 25 of the 200 cost units/hour
```

Ceilings are counted in cost units per hour: every action costs 1 unless
`budget.weights` raises it. Sanity-check it:

```bash
grenz policy check
```

## 4. Run + connect (1 min)

```bash
grenz run
```

Point your MCP client at `http://127.0.0.1:8787/u/linear`, authenticating with
the **GRENZ_TOKEN** from step 1 (as `Authorization: Bearer <GRENZ_TOKEN>`).
The agent never sees `linear_token`.

### See allow vs deny with `curl` (GitHub, no MCP client)

The scaffolded GitHub upstream is the fastest way to watch the firewall decide.
Even a **fake** `github_token` works for this — the deny path never reaches
GitHub, and the allow path proves forwarding regardless of what GitHub says back:

```bash
G="Authorization: Bearer $GRENZ_TOKEN"      # from step 1

# ALLOWED (repo:read) — Grenz forwards; GitHub answers (200 with a real token,
# 401 with a bad one). Either way, GitHub answered, so Grenz let it through.
curl -s -o /dev/null -w '%{http_code}\n' -H "$G" \
  http://127.0.0.1:8787/u/github/repos/acme/app

# DENIED (repo:delete) — Grenz answers 403 itself; the request never leaves the proxy.
curl -s -X DELETE -H "$G" http://127.0.0.1:8787/u/github/repos/acme/app
# → {"error":"explicit_deny","decision":"deny","action":"repo:delete","tool":"github"}
```

The tell: a **deny** is Grenz's own `403 explicit_deny` JSON; an **allow** is
whatever GitHub replied (Grenz got out of the way). No credential appears in
either response.

## 5. Watch it live (1 min)

```bash
cd console && bun install && bun run dev     # → http://localhost:4180
```

You'll see every request with its decision. When the agent calls a
`call:delete_*` tool, the request **blocks** and a pending approval appears —
click **Approve** or **Deny** (or use `grenz approve <id>` / `grenz deny <id>`
from the terminal). No decision within 5 minutes → the request is denied.

The agent's connection is held while you decide, up to ~255 seconds (Bun's
socket ceiling). If you take longer than that, the connection drops and the
agent must retry to get a fresh prompt — so approve promptly, or wire up the
Slack push below so you're not the bottleneck.

Optional: get pinged in Slack when something needs approval:

```bash
printf %s "$SLACK_WEBHOOK_URL" | grenz vault set slack_webhook
```

---

## That's the 5-minute path — here's what you built

- The agent holds only a `GRENZ_TOKEN`; the real credential stays inside the
  proxy and is injected only on allowed, outbound requests.
- Reads flow through; deletes require a human tap; everything else is denied by
  default.
- A local, truncatable SQLite log and a live console give you visibility — with
  no credential material anywhere in them.

You have a protected agent. **Everything below is optional** — reach for a
section when you hit the problem it solves; you don't need any of it to start.

## Going further (optional)

**Runtime defense-in-depth** — gates that watch the live request stream:
- [`flows`](#optional-gate-read--exfil-sequences-flows) — block read → exfil
  sequences (the "lethal trifecta") even when each action is individually legal.
- [`tripwires`](#optional-hair-trigger-tripwires-tripwires) — hard backstop: the
  mere *attempt* at a poisoned action trips the kill-switch.
- [`pins`](#pin-a-session-to-its-working-target-pins) — keep one session from
  roaming off the target it started on.
- [`responses`](#cap-how-much-data-a-read-can-return-responses) — cap the *bytes*
  an allowed read can pour into the agent's context.

**Policy lifecycle** — author, tighten, and re-certify from real usage:
- [`shrinkwrap`](#tighten-a-broad-policy-from-real-usage-shrinkwrap) · [`decay`](#re-certify-grants-that-have-gone-quiet-decay) · [`--canary`](#preview-a-tighter-policy-before-you-enforce-it---canary)

**Team & fleet** — many operators, many proxies:
- [named tokens & roles](#team-operators-with-roles-grenz-token) · [break-glass](#break-the-glass-in-an-emergency-grenz-break-glass) · [HashiCorp Vault](#use-hashicorp-vault-for-secrets) · [signed policy distribution](#sign-the-policy-you-ship-to-a-fleet-grenz-policy-sign) · [fleet-wide revocation](#kill-an-agent-across-the-fleet-grenz-revocations-sign)

## Optional: gate read → exfil sequences (`flows`)

Individually-legal actions can combine into an attack: an agent reads
attacker-controlled content (an issue, a comment, a file), then writes it to an
external sink (a Slack post, a PR comment). Each action passes policy; the
*sequence* is the compromise (the "lethal trifecta"). Because Grenz sees every
request in real time, it can gate the combination:

```yaml
flows:
  - when: ["*:read", "call:get_*"]   # taint SOURCES (action globs)
    then: ["call:*", "issue:comment"] # SINKS gated once a source was seen
    effect: require_approval          # or "deny"; default require_approval
    within_seconds: 3600              # a source taints for this long
```

Once the agent performs any `when` action, a subsequent `then` action within the
window blocks for approval (or is denied). Matching is **cross-tool by design** —
the read may be on one upstream and the write on another. Facts are ephemeral
and in-memory: a proxy restart clears them, and nothing is written to the request
log. A flow only *escalates* — it never overrides an explicit `deny` and never
widens an allow.

Note the socket ceiling from the approvals section applies: a flow that escalates
to `require_approval` holds the connection up to ~255s like any other approval.

Check for typos before you rely on it (a mistyped sink silently gates nothing):

```bash
grenz policy lint   # flags dead flow when/then patterns
grenz explain github pr:merge   # shows "flow:" if the action is a sink
```

## Optional: hair-trigger tripwires (`tripwires`)

Where `flows` gates a *sequence*, a tripwire is a hard, deterministic backstop:
declare action/target patterns whose **mere attempt** — even an action the policy
would deny anyway — instantly trips the kill-switch. The actor is revoked, the
request is denied (`tripwire`), and (if configured) you get a Slack ping.

```yaml
tripwires:
  - action: "*:admin"           # any admin-surface attempt...
  - action: "*:delete"
    targets: ["prod-*"]          # ...or a delete against a prod target
    note: "prod deletes are off-limits"
```

Any agent that so much as *asks* for a tripwired action is cut off — reinstate
it deliberately with `grenz restore <agent>`. This is a poison pattern, not a
budget: use it for surfaces no legitimate task should ever touch.

Because a tripwire fires even on an action your policy *allows*, a pattern that
overlaps an `allow` makes the agent self-revoke on normal work — `grenz policy
lint` flags that overlap, and `grenz explain <tool> <action>` prints a loud
`tripwire:` line when an action is wired.

## Pin a session to its working target (`pins`)

A usable policy is target-broad — `repo:*` across `acme/*`. But one *session*
shouldn't roam: an agent that reads `acme/api` has no business then writing to
`acme/payroll`. Scoped grants can't catch this (the glob matches both), and
`blast-radius` only measures the *static* reach. Pinning is its runtime dual:

```yaml
pins:
  - key: "^/repos/([^/]+/[^/]+)"   # capture group 1 = the target unit (here: owner/repo)
    on: ["issue:update", "pr:merge", "repo:delete"]  # these establish + are constrained
    effect: require_approval        # or deny; default require_approval
    within_seconds: 3600            # pin lifetime; default 1h
```

The **first** matching action in a session pins it to that unit (e.g. `acme/api`).
Acting on the same unit is free; acting on a **new** unit (`acme/payroll`)
escalates to approval (or denies). Reads aren't listed in `on`, so an agent still
reads broadly — pinning governs only the mutating side you name. A delegated
sub-token **inherits its parent's pins**, so spawning a sub-agent is not an
escape hatch.

The pin unit comes from a regex capture over the request target, so a bad `key`
(no capture group) is a compile error, not a silent no-op. The `key` matches
**case-insensitively** — a pin that misses its target goes inert, and an inert
pin is a hole, so `/REPOS/acme/api` must not be a way around one. The captured
unit itself is still compared exactly, so a case-shifted unit escalates rather
than being merged with the pinned one. `grenz policy lint`
flags an `on` glob that matches no known action, and `grenz explain <tool>
<action>` prints a `pin:` line for a constrained action. Pins are ephemeral and
in-memory — a restart clears them, nothing extra is logged, and the gate can only
*tighten* a decision. Pre-action defense-in-depth, not an audit trail.

## Cap how much data a read can return (`responses`)

Grenz gates the *verb* — but an allowed `repo:read` can still pour an entire
repository into your agent's context. `responses` caps the *bytes* a read
returns. It counts bytes and cuts the stream; it never inspects, buffers, or
redacts content, so SSE and large payloads still stream.

```yaml
responses:
  - on: [repo:read, contents:read]   # action globs to cap
    targets: ["*"]                    # optional target globs (default: all)
    max_bytes: 262144                 # 256 KiB
    on_exceed: truncate               # truncate (default) | deny

  - on: ["call:search_*"]             # a tighter cap for a chatty MCP tool
    max_bytes: 65536
    on_exceed: deny
```

- `truncate` (default): the body streams up to `max_bytes`, then the stream is
  cut. The response stays `200` and carries `x-grenz-response-limit: <bytes>`.
- `deny`: an oversized response is refused with `413 response_too_large` and no
  body — but only when the upstream *declares* a `content-length`. A chunked or
  SSE response has no declared length, so `deny` there degrades to a hard
  truncation (a `200` already in flight cannot become a `413`).

Scope `on` to **reads**. The size check runs *after* the upstream request, so a
`deny` on a mutating action (a `POST` that already committed) still returns `413`
to the agent — inviting a retry that mutates again. Caps are for read volume;
keep write actions out of `on`.

The tightest matching cap always wins, including across the actions of an MCP
batch — a batch can't dodge a cap by bundling a capped read with an uncapped one.
`grenz policy lint` flags an `on` glob that matches no known action, and `grenz
explain <tool> <action>` prints a `responses:` line for a capped action.

> This caps SIZE, never content. Nothing here inspects, classifies, or logs the
> bytes that come back — it counts them and trims the stream. It is the read-side
> dual of request-body DLP: least-data-out becomes least-data-in.

## Tighten a broad policy from real usage (`shrinkwrap`)

Most policies start too broad — a template or a `repo:*` grant — and never get
tightened. Once your agent has run for a while, let its own traffic write the
tighter policy:

```bash
grenz policy shrinkwrap > tight.yaml     # or: --hours 168 to look back a week
grenz policy diff tight.yaml             # see exactly what it drops
```

`shrinkwrap` reads the local log, finds the actions the agent *actually* used
(only ones it exercised under a policy `allow`), and rewrites each grant's
`allow` to exactly those — printing a delta like `github: 41 reachable → 9 used
(dropped 32)`. It **only ever tightens**: `deny` and `require_approval` are
preserved untouched (an approval-gated action is never promoted to a bare
allow), and it verifies the result still permits everything you used before
emitting it.

This is policy authoring *from* operational data — not a usage report or audit.
The log stays a plain, truncatable operational store; shrinkwrap just reads it as
a starting point you review and apply.

## Re-certify grants that have gone quiet (`decay`)

Agent permissions only ever grow — nobody takes back the `pr:merge` you added
for a one-off. `grenz policy decay` is the access-review pass: it flags `allow`
grants the agent has **not exercised within a staleness window** and proposes
downgrading them. It's shrinkwrap's time-aware sibling — shrinkwrap asks *what
has this agent used*, decay asks *what has it stopped using*.

```bash
grenz policy decay > candidate.yaml            # demote anything quiet 30+ days (dry run)
grenz policy decay --drop --stale-days 60      # or drop it outright, 60-day window
grenz policy decay --report-only               # just the classification, no YAML
grenz policy diff candidate.yaml               # see exactly what changes, then apply
```

**Demote is the default and the fail-safe.** A wrongly-decayed grant becomes an
approval prompt the next time the agent needs it (a re-certification checkpoint,
TTL 5 min → DENY), not a silent outage. `--drop` removes it entirely. Decay
never touches `deny`, `require_approval`, targets, or budgets, and it verifies
every still-active action decides identically before emitting — so it can only
tighten, never break a live workflow. This bounded harm ceiling — the worst a
wrong or tampered log can do is add an approval prompt — is exactly *why* the log
never needs integrity guarantees.

**Watch for cyclical capabilities before you accept a candidate.** An action used
on a cadence longer than `--stale-days` (a quarterly `actions:dispatch`, a
monthly report) looks stale to decay. The report shows each action's use count
(`47x`) to help you spot these — widen `--stale-days`, or keep the grant, rather
than demote a real-but-infrequent capability on an unattended agent.

Apply it the same way you'd apply any candidate: review, `diff`, then adopt via
`--watch` (local) or `grenz policy sign candidate.yaml --version <N+1>` (fleet).
Decay never enforces and never writes your policy itself — it refuses to write
over the live `policy.yaml`.

**Truncating the log is safe.** The log is plain, truncatable SQLite. Decay
treats *absence* of usage as "no evidence" — never "unused." If the log is empty
or younger than your staleness window, decay proposes no changes and tells you
why. It will never strip a policy just because the log was cleared.

### Fleet-wide evidence (multi-proxy)

Under signed distribution one agent runs on many proxies, and each log sees only
its slice of traffic. Before demoting, gather what the whole fleet actually uses:

```bash
# On each proxy: export this proxy's usage for the agent.
grenz policy decay export --proxy us-east-1a > usage-us-east.json
grenz policy decay export --proxy eu-west-1  > usage-eu-west.json

# On your workstation: merge the peers into the decay run.
grenz policy decay --evidence usage-us-east.json,usage-eu-west.json > candidate.yaml
```

A grant idle on this proxy but **used on a peer** is kept (marked `(fleet)` in the
report), not demoted. Fleet evidence can only *keep* a grant — it never causes a
demotion and never lengthens the observation window, so merging peer data is
always safe. A snapshot older than your staleness window is flagged (that proxy's
recent activity is unknown — re-export it). Evidence files carry only
tool/action/timestamps for the named agent — no credentials, no targets, no
request bodies.

Note: "used" counts every real exercise — including actions run through an
approval prompt, a schedule/taint gate, or a temporary JIT grant. This is
deliberate: a capability the agent still reaches, even under a gate, is not
stale. A grant used *only* through approvals will therefore not decay.

## Preview a tighter policy before you enforce it (`--canary`)

`shrinkwrap` (or a hand edit) gives you a *tighter candidate* policy, but
adopting it on a live agent is scary: will it block legitimate work you didn't
anticipate? The **canary** answers that on real traffic — without enforcing the
candidate. Start the proxy with the candidate alongside the enforced policy:

```bash
grenz run --canary tight.yaml
```

The live policy still decides every request. For each one, Grenz also evaluates
the candidate (pure engine, no extra network) and records where the two verdicts
*diverge*. Let it observe a representative window of traffic, then:

```bash
grenz policy canary
```

```
canary — 1204 requests observed, 37 divergences
  would newly BLOCK (promotion risk):
    github issue:list  allow → deny  18×
    github repo:read   allow → require_approval  9×
  would newly ALLOW (widening):
    linear comment:delete  deny → allow  10×
  → if the BLOCK list is all expected, apply the candidate (diff, then --watch)
```

When the **BLOCK** list contains only actions you *intend* to cut off, promote:
`grenz policy diff tight.yaml` for a final retrospective check, then swap it in
(`grenz run --watch` picks up an edited `policy.yaml`). The canary is
report-only and in-memory — a restart clears it, and the candidate never affects
a live decision.

This completes the authoring-safety loop: `policy test` (synthetic assertions),
`policy diff` (retrospective on history), **canary** (forward-looking on live
traffic).

## Team operators with roles (`grenz token`)

The console/admin API starts with one bootstrap admin token (`admin.token` in
your Grenz home). For a team, mint **named tokens** with roles instead of
sharing that one secret:

```bash
grenz token create alice --role approver
grenz token create bob   --role approver
grenz token create carol --role admin
grenz token list
```

Roles are **viewer** (read the console), **approver** (viewer + resolve
approvals), and **admin** (everything: grants, revocations, delegations, token
management). Every console route is gated deny-by-default — an unknown token is
`401`, a token without the required role is `403`.

This makes **quorum a real control**: when a policy needs two approvers, Grenz
counts *distinct authenticated tokens*, not self-asserted labels. One person
holding one token can no longer satisfy a 2-person quorum — and the bootstrap
token is a single identity that can never settle a quorum ≥ 2 alone. The approver
recorded on each decision is the token's name: operational separation of duties,
not an audit log.

Revoke an operator instantly with `grenz token revoke alice`. The bootstrap
token always remains as break-glass. (`grenz approve`/`deny` no longer take
`--as` — the approver is whichever admin token you authenticate with.)

> **Federating operators to your IdP (`grenz login`, OIDC)** — binding operator
> tokens to your identity provider so offboarding a person expires their access
> automatically — is part of **Grenz Enterprise**. See [docs/enterprise.md](enterprise.md).

## Break the glass in an emergency (`grenz break-glass`)

Prod is down at 3am and the agent needs an action your policy **denies**. Nothing
else in Grenz touches an explicit `deny` — that's deliberate. Break-glass is the
one exception: an admin unlocks a denied action for a short, loud, attributed
window, and each request in that window still gets a human tap.

```bash
grenz break-glass claude-code --action "pr:merge" --reason "prod hotfix" --quorum 1 --ttl 600
```

That does **not** silently allow `pr:merge`. It rewrites the deny into a fresh
`require_approval` for the scoped agent + actions — so the otherwise-hard-denied
action becomes *approvable*, and a human (often the same admin, awake and already
in Slack) taps to approve each concrete request. The window declares its own
quorum, which may be **1** — separation of duties is explicitly, loudly suspended
by a named admin, not silently bypassed. A `:rotating_light:` Slack message fires
the moment the glass breaks, attributed to your admin token.

What break-glass will **not** do, by construction: bypass the kill-switch or a
tripwire (a revoked/tripwired agent stays cut off), exceed a delegation's scope,
or override the behavioral gates — a taint-flow or session-pin violation
mid-emergency still denies. It *does* suspend a closed business-hours schedule
(that's exactly the rule a 3am emergency legitimately lifts).

```bash
grenz break-glass                 # list active windows (who pulled, scope, expiry)
grenz revoke <bg-id>              # end a window early (the kill-switch)
```

Windows auto-expire (default 15 min, cap 60) and there's no renewal — re-pull,
which re-notifies. The window record is plain, truncatable operational state with
an admin token name for attribution: emergency access control and separation of
duties, **not** an audit trail.

## Use HashiCorp Vault for secrets

By default Grenz reads upstream credentials from its local age-encrypted vault.
An enterprise's secrets already live in HashiCorp Vault, with their own ACLs,
rotation, and change process — so point Grenz at Vault instead:

```yaml
# .grenz/grenz.yaml
credential_store:
  type: hashicorp-vault
  address: https://vault.corp.example.com
  mount: secret          # KV v2 mount (default "secret")
  path_prefix: grenz/   # secrets live at secret/data/grenz/<credential> (default)
  field: value           # which field of the KV item holds the secret (default "value")
```

Grenz is a **read-only consumer** — you manage secrets in Vault's own UI/CLI
(`vault kv put secret/grenz/github_token value=ghp_…`); Grenz never writes to
Vault. Give it a **least-privilege token** with only `read` + `list` on
`secret/data/grenz/*`, and provide that token either via the environment
(`VAULT_TOKEN`, wins if set — ideal for CI/K8s) or the local vault
(`grenz vault set hashivault_token`).

On an allowed request, Grenz fetches the credential from Vault (5s timeout,
cached in memory for `cache_ttl_seconds`, default 60), injects it into the
outbound request, and — like always — never shows it to the agent. A bad token or
unreachable Vault fails **loudly at `grenz run`**, not as a storm of 502s later.
The credential still lives only inside the proxy; this just changes where the
proxy fetches it from. (Not an audit surface — Grenz consumes Vault as the system
of record.)

## Point a proxy at a control plane (`grenz connect`)

A control plane distributes policy to a fleet: each proxy pulls the current
rules on a clock. Decisions still happen **in the proxy**, offline, on the last
policy that arrived — the plane never sees a request and never decides one.

One command per machine:

```bash
grenz connect https://plane.example.com/api/policy/my-agent
# Paste the pull token (input hidden):
#
#   connected to plane.example.com
#   policy   pulls every 300s, refuses to serve one older than 3600s
#   bundle   unsigned — anyone who can serve this URL chooses the policy
#   stats    off — add --telemetry to report aggregate counts
```

It stores the token in the vault and writes the `policy_source` block into
`grenz.yaml`, keeping your comments and formatting. The token is typed into a
prompt rather than passed as an argument, so it never reaches your shell history
or the process table — pipe it in (`printf %s "$TOKEN" | grenz connect …`) for
unattended installs.

| Flag | What it does |
| --- | --- |
| `--public-key <b64>[,<b64>]` | Require a signed bundle, pinning these keys. Repeat with commas to rotate. |
| `--telemetry` | Also report aggregate per-tool/action counts. Off unless asked for. |
| `--force` | Replace an existing `policy_source`/`telemetry` block. |

Connecting refuses plain `http` off localhost: the org token and the policy both
travel that URL, so over http anyone on the path both learns the token and
chooses your policy. It also refuses to overwrite an existing `policy_source`
without `--force` — that block may pin a `public_key`, and silently replacing it
would downgrade you from verified distribution to trusted-transport.

`grenz doctor` reports whether the vault key the block names is actually there.
It checks that the key *exists*, not that the plane accepts it — a stale token
passes `doctor` and fails at the next pull.

### What happens when the plane says no

`connect` writes `refresh_seconds: 300`, `max_age_seconds: 3600` and
`on_stale: fail_closed`, and all three apply whether or not you pinned a key:

- Every 300s (jittered ±10%) the proxy re-pulls. A pull that fails — plane down,
  token revoked, policy that will not compile — leaves the running policy in
  force and does **not** advance the liveness clock.
- When nothing has been verified inside `max_age_seconds`, `fail_closed` swaps
  the proxy to a zero-grant policy: it denies everything until a fresh pull
  lands, then heals itself automatically.
- A proxy that has **never** pulled counts as infinitely stale. If your very
  first pull is rejected, the proxy starts and denies rather than quietly
  serving the local `policy.yaml` you were not asking it to enforce.

Use `on_stale: warn` if you would rather keep enforcing the last-good policy
through a plane outage. That is the default for a hand-written `policy_source`;
`connect` opts you into the stricter one.


## Sign the policy you ship to a fleet (`grenz policy sign`)

Grenz can pull its policy from a control plane (`policy_source`) so a fleet of
proxies converges on one set of rules. But the plane then distributes *the thing
that decides* — and if it were compromised, it could push a maximally-permissive
policy to every proxy you run.

Signing removes the plane from that trust position. You sign the policy with a
key the plane never holds; each proxy verifies against a public key you pinned
by hand. The plane can then serve only what you already signed.

**1. Generate the org signing keypair** — once, on your workstation:

```bash
grenz policy keygen --out signing.key
# Private key written to signing.key (mode 0600).
# public key:  BvlQc0B/Us…   <- paste into every proxy
```

`--out` writes the bare private key to a 0600 file — the exact format
`sign --key` reads. (Plain `grenz policy keygen` prints both keys to stdout
instead, if you would rather copy them into a secret store by hand.)

The **private key never goes on a proxy or the plane**. Put `signing.key` in
your CI secret store; that is where signing happens.

**2. Pin the public key** in each proxy, delivered out-of-band (hand it to
operators directly — not through the plane you are trying to distrust):

```bash
grenz connect https://plane.example.com/policy/bundle --public-key "BvlQc0B/Us…"
```

or by hand in `grenz.yaml`:

```yaml
# .grenz/grenz.yaml
policy_source:
  url: "https://plane.example.com/policy/bundle"
  org_token_key: cloud_org_token
  public_key: ["BvlQc0B/Us…"]   # >=1 key REQUIRES a signed bundle
  refresh_seconds: 300          # re-pull every 5 min (jittered); 0 = startup only
  max_age_seconds: 3600         # optional: flag a policy this stale
  on_stale: warn                # warn (default) | fail_closed
```

**3. Sign a version and publish it** — from CI, on every policy change:

```bash
umask 077
printf '%s' "$GRENZ_SIGNING_KEY" > signing.key   # bare base64, nothing else
grenz policy sign policy.yaml --key signing.key --version 7 > bundle.json
rm -f signing.key
# serve bundle.json at the policy_source URL
```

Bump `version` on every policy change. Each proxy persists the highest version it
has accepted and **refuses anything below it**, so an attacker who captures an
old signed bundle cannot replay it to quietly re-widen a fleet. Between changes
the plane keeps serving the current version, which every proxy re-verifies and
accepts as-is — that is the healthy steady state, and it is what keeps the
freshness clock below ticking. Signing also refuses a policy that does not
compile, so you can never publish a broken one.

At startup and on each refresh the proxy verifies the signature, checks the
version, recompiles, and swaps the policy in atomically. Anything that fails —
bad signature, replayed version, unreachable plane, policy that will not
compile — leaves the **last-good policy in force**. It never fails open. The
banner and `/metrics` show what is actually running:

```
policy dist:  signed (refresh 300s ±10%) — running v7 (a3f9c1d0e2b4)
```

```
grenz_policy_version 7
grenz_policy_seconds_since_pull 42
```

Rotate a key by listing both (`public_key: ["old…", "new…"]`), re-signing with
the new one, then dropping the old.

### Ship per-agent profiles in the bundle

[Per-agent policy profiles](../README.md#per-agent-policy-profiles--different-grants-for-different-agents)
give one agent its own `allow`/`deny`/`require_approval` grants instead of
sharing the default policy. Sourced from a local `file:` they stay
per-proxy; a signed bundle can carry them fleet-wide instead.

Declare the name in every proxy's `grenz.yaml` with no `file:` — a name-only
entry (`ci: {}`, or a bare `ci:`) says "this profile's content arrives over
the bundle":

```yaml
policy_profiles:
  ci: {}                          # name-only — content comes from the bundle
```

Then sign it in alongside the default policy, one `--profile name=path` per
profile (comma-separated for more than one — **not** repeated `--profile`
flags; the parser keeps only the last one it sees):

```bash
grenz policy sign policy.yaml --key signing.key --version 8 \
  --profile ci=profiles/ci.yaml,triage=profiles/triage.yaml > bundle.json
```

The bundle is a v2 signed message once it carries `profiles` at all — the
field's *presence* is bound into the signature, not just its contents, so
stripping or injecting a `profiles` array from an already-signed bundle
invalidates it rather than silently downgrading it to a plain default-only
bundle.

**Every content change bumps `--version`** — a profile edit is a policy
content change exactly like an edit to the default, and gets no free pass
just because it's a profile.

`grenz policy` history reflects only the default policy YAML the proxy adopts,
not per-profile changes, for now — a profile edit still reaches the fleet, it
just does not land as its own history snapshot yet.

**A declared-but-undelivered name denies, it does not fall back.** If
`policy_profiles` names `ci` but the bundle you signed doesn't include a
`ci` entry, any agent on `policy: ci` denies every request
(`agent_policy_unresolved`) rather than quietly running the shared default —
a silently-widened agent is worse than a loud one that stops working.

**No `--profile`/`--clear-profiles` on a home that declares
`policy_profiles` is a hard error**, not a silent no-op:

```
grenz: this home declares policy_profiles — pass --profile name=path for each, or --clear-profiles
```

This is deliberate: `sign` never statefully "remembers" the last profile
set and carries it forward, because that would need the signer to trust
its own local disk as an implicit source of truth. Making omission an
error means a routine re-sign can never *accidentally* drop the fleet's
profiles — you either name them again or explicitly clear them:

```bash
grenz policy sign policy.yaml --key signing.key --version 9 --clear-profiles > bundle.json
```

Once that lands, every profile-bearing agent starts denying
`agent_policy_unresolved` — the same as an absent `profiles` field on any
bundle. **Signed mode never freezes a profile set on the last thing it saw**;
an absent-or-cleared field is read as "no profiles right now," full stop.

`--force-version` re-signs a **same-numbered** version while you iterate
locally: it bypasses the sign-time version-bump usability check
(`.grenz/last-signed-version`) only. Be precise about what the proxy's
anti-rollback floor does: it refuses anything **strictly below** the last
version it accepted, but a **same-numbered** bundle is always adopted — every
bundle at a given version is interchangeable. So the previously-signed bundle at
that version stays replayable, and re-signing it does not "win." Any content
change you want to reach the fleet — **especially a tightening** — MUST bump
`--version` (the "every content change bumps `--version`" rule above).
`--force-version` is for local iteration only; never use it to push tightened
content at an already-accepted version, because a proxy that already holds that
version will not adopt your change.

> **What this signs, and what it does not.** This is supply-chain integrity for a
> control **input**: it proves the rules your proxy enforces are the rules your
> org authored. It is the same shape as verifying an OIDC `id_token` — check the
> input's authenticity at load time, then discard the crypto. It says nothing
> about, and produces nothing from, what your agents did afterward.

## Kill an agent across the fleet (`grenz revocations sign`)

`grenz revoke <agent>` cuts an agent off on **one** proxy. In Grenz the agent
never held the upstream credential, so cutting the principal *is* the whole
containment story — there is no leaked secret to rotate afterward. To make that
kill-switch fleet-wide, publish a **signed revocation set**: a current-state list
of the agent ids that are cut off right now, over the same pinned key your policy
uses. Every proxy unions it with its own local revocations, so revoking once
propagates within the refresh interval — provided `revocation_refresh_seconds > 0`.
With the default (`0`, startup-only), a **running** proxy adopts a new set only on
its next restart, so set a refresh interval for live fleets.

```bash
# Cut off scraper-bot everywhere. Ids come from stdin; reuse your policy key.
printf 'scraper-bot\n' | grenz revocations sign \
  --key signing.key --version 12 --expires-in 3600 > revocations.json
# Serve revocations.json at policy_source.revocation_url.
#   restore one id:      re-sign the set WITHOUT it at a HIGHER version
#   un-revoke everyone:  sign an empty set — printf '' | grenz revocations sign ...
#   publish this box's local set:  grenz revocations sign --from-local ...
```

```yaml
policy_source:
  url: "https://plane.example.com/policy/bundle"
  public_key: ["<base64-ed25519-pubkey>"]     # shared trust root
  revocation_url: "https://plane.example.com/revocations"
  revocation_refresh_seconds: 60              # own, shorter clock than policy
  revocation_max_age_seconds: 900             # optional staleness bound
  on_revocation_stale: warn                   # warn (keep denying) | fail_closed (deny all)
```

Like the policy bundle, each set carries a monotonic `version` and the proxy
**refuses anything below the highest it has accepted** — an attacker cannot
replay an older set to quietly un-revoke someone. The set is cached to disk, so a
plane outage never un-revokes the fleet: the cached set stays enforced, and a
local `grenz revoke` or a fired tripwire is never overridden by a fleet sync.
`grenz restore` on a fleet-cut agent tells you the truth — only a new signed set
restores it. Staleness runs the *safe* direction: a stale set keeps denying;
`on_revocation_stale: fail_closed` (with a bound, plus an optional signed
`--expires-in`) denies **everything** until a fresh set lands. The banner and
`/metrics` show what is running:

```
fleet revoke: signed (refresh 60s ±10%, warn) — v12 (1 cut off)
```

```
grenz_revocations_fleet 1
grenz_revocation_set_version 12
grenz_revocation_seconds_since_pull 8
```

> **What this signs, and what it does not.** This signs a control **input** — the
> current revocation set (who is cut off *now*) — not a record of what happened.
> No reason, actor, or timestamp is ever signed; those stay local, unsigned, and
> truncatable. A signed *set* is a CRL; a signed *stream of revocation events*
> would be signed history — Grenz does not build that.
