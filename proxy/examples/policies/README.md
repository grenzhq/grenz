# Example policy pack

Ready-to-copy starting policies for common agent tools. Every one is
**deny-by-default**: an action that isn't listed under `allow` (or
`require_approval`) is denied. Pick the one closest to your agent, copy it, and
tighten from there.

## The packs

| File | Tool | Posture | Use it when |
|------|------|---------|-------------|
| [`github-read-only.yaml`](github-read-only.yaml) | `github` | Read-only — look, never touch | Research / triage / review agents |
| [`github-safe-defaults.yaml`](github-safe-defaults.yaml) | `github` | Reads + opens/comments PRs & issues; **no merge, no repo/CI writes** | A coding agent that should propose changes via PRs |
| [`linear-semantic.yaml`](linear-semantic.yaml) | `linear` (semantic adapter) | Reads freely; **writes need a human tap**; deletes denied | Linear over the `type: linear` adapter |
| [`slack-semantic.yaml`](slack-semantic.yaml) | `slack` (semantic adapter) | Reads channels/history; **posting & reactions need approval**; uploads denied | Slack over the `type: slack` adapter |
| [`mcp-linear.yaml`](mcp-linear.yaml) | `linear` (generic MCP) | Read-only tools + a couple of creates; deletes/updates need approval | Wrapping a raw MCP server by its real tool names |

Posture climbs left→right: start at `read-only`, move to `safe-defaults`, and
only add writes you actually need.

## How to use one

1. **Copy it** into your project (e.g. `cp github-safe-defaults.yaml ./policy.yaml`)
   and point `grenz.yaml` at it, or paste its `grants:` into your policy.
2. **Set `agent` and `on_behalf_of`** to real values (they're placeholders here).
3. **Pair it with an upstream** in `grenz.yaml`. The semantic/MCP packs carry the
   matching `upstreams:` block in their header comment — for example:

   ```yaml
   upstreams:
     linear:
       type: linear
       base_url: https://mcp.linear.app/sse
       credential: linear_token
   ```
4. **Validate before you run:**

   ```sh
   grenz policy check   # compile + summary — does it parse and bind?
   grenz policy lint    # dead patterns, unreachable rules, and other smells
   ```

## The grammar in 60 seconds

```yaml
agent: claude-code            # who this policy is for
on_behalf_of: you@example.com # the human the agent acts for

grants:
  - tool: github              # one block per upstream tool
    allow:      [pr:read]     # permitted outright
    require_approval: [pr:merge]  # blocked until a human approves (TTL 5 min → deny)
    deny:       [repo:delete] # never — deny OUTRANKS allow

budget:
  max_actions_per_hour: 300   # throttle; over-budget actions are denied

dlp:                          # scan outbound bodies for secret shapes
  scan_bodies: true
  on_match: deny              # deny | require_approval
```

- **Deny-by-default.** No blanket `deny: ["*"]` is needed — anything not granted
  is already denied. (A `deny: ["*"]` would be wrong: deny outranks allow, so it
  would also block your reads.)
- **Patterns** are exact (`pr:read`) or wildcarded (`actions:*`, `call:list_*`).
- **`require_approval`** parks the action and asks a human; it expires to DENY.

## Semantic adapter vs. generic MCP

Two of these wrap Linear — on purpose, to show the difference:

- **`linear-semantic.yaml`** uses the `type: linear` adapter's canonical taxonomy
  (`issue:read`, `issue:write`, `comment:delete`, …), mapped from Linear's real
  MCP tools. Rules read like intent.
- **`mcp-linear.yaml`** uses the generic `type: mcp` adapter and matches the
  server's raw tool names via `call:<tool>` (`call:create_issue`, `call:delete_*`).
  Use this for any MCP server that doesn't yet have a semantic adapter.

## Adding a pack

New tool? Add an adapter in [`../../src/adapters`](../../src/adapters) with its
taxonomy, drop a policy here, and add tests. Contributions welcome.
