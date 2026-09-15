# Quickstart: put an OpenClaw agent behind Grenz

[OpenClaw](https://docs.openclaw.ai) is a self-hosted AI agent that runs 24/7 on
your own box — it watches your repos, reads your files, runs commands, and acts
on a schedule through your chat apps. To do that it holds your real
credentials: your GitHub PAT sits in plaintext in `~/.openclaw/openclaw.json`,
and the agent authenticates to GitHub as *you*, with everything your token can
do.

That setup has two problems, and Grenz answers both with the same binary:

- **The agent is always on and always acting.** A prompt-injected task ("close
  every stale issue") or a bad plan can merge, delete, or dispatch CI while
  you're asleep. Grenz gates each action *before* it happens — reads flow,
  irreversible actions pause for your approval.
- **The credential is sitting in a config file.** An infostealer or a
  trojanized MCP server doesn't need to break the model; it just reads
  `openclaw.json` and walks off with your PAT. After Grenz, that file holds a
  `GRENZ_TOKEN` that is worthless anywhere but your own loopback — the real
  token never leaves the proxy.

The catch with a 24/7 headless agent is approvals: when a `merge` blocks for a
human, there's no one at that machine's keyboard. That's what **[Grenz
Relay](relay.md)** is for — the approval lands on your phone via Slack, you tap
Approve, and the verdict comes back to the proxy. Relay is the spine of this
quickstart, not an afterthought.

## What changes in OpenClaw

OpenClaw reaches GitHub through the remote GitHub MCP server. Before Grenz, that
entry in `~/.openclaw/openclaw.json` points straight at GitHub and carries your
real PAT:

```json
{
  "mcp": {
    "servers": {
      "github": {
        "url": "https://api.githubcopilot.com/mcp/",
        "transport": "streamable-http",
        "headers": { "Authorization": "Bearer ghp_yourRealPAT" }
      }
    }
  }
}
```

After Grenz, the same entry points at your local proxy and carries a
`GRENZ_TOKEN` instead — two lines change, and nothing else about OpenClaw does:

```json
{
  "mcp": {
    "servers": {
      "github": {
        "url": "http://127.0.0.1:8787/u/github-mcp",
        "transport": "streamable-http",
        "headers": { "Authorization": "Bearer <YOUR_GRENZ_TOKEN>" }
      }
    }
  }
}
```

The rest of this page sets up the proxy behind that URL.

## 0. Build the CLI (once)

```bash
git clone https://github.com/grenzhq/grenz && cd grenz
bun install
cd proxy && bun run build      # → ./proxy/dist/grenz
export PATH="$PWD/dist:$PATH"  # so `grenz` is on your PATH
cd ..
```

## 1. Initialize a home outside your repos (30s)

```bash
export GRENZ_HOME="$HOME/.grenz"   # one home, outside every worktree
grenz init
```

This scaffolds the home (age identity, encrypted vault, admin token, config,
policy) and prints your **GRENZ_TOKEN once** — copy it; it's the value you'll
paste into `openclaw.json` in step 6.

> **Keep the home outside your worktrees.** Without `GRENZ_HOME`, `grenz init`
> uses `./.grenz` — putting the vault and admin token *inside a repo the agent
> works in*, so the agent could read its own vault and recover the real PAT. One
> global home (and one `grenz run`) is the boundary. On an always-on box, keep
> the proxy up across reboots with `grenz service install`.

## 2. Add the GitHub MCP upstream (1 min)

Edit `$GRENZ_HOME/grenz.yaml` and register the GitHub MCP server as an upstream:

```yaml
upstreams:
  github-mcp:
    type: mcp
    base_url: https://api.githubcopilot.com/mcp/
    credential: github_pat
```

Put the real PAT in the vault (read from stdin, so it never lands in your shell
history or a process list):

```bash
printf %s "$GITHUB_PAT" | grenz vault set github_pat
```

From here on the PAT lives only in the age-encrypted vault and is decrypted only
inside the proxy, injected onto the outbound request to GitHub as
`Authorization: Bearer …`. OpenClaw never sees it again.

## 3. Write the policy (1 min)

Edit `$GRENZ_HOME/policy.yaml`. The GitHub MCP server exposes its actions as
`call:<tool_name>` (e.g. `call:merge_pull_request`, `call:delete_file`), so you
gate by tool name. Deny-by-default; precedence is
deny > require_approval > allow:

```yaml
agent: openclaw
on_behalf_of: you@example.com
grants:
  - tool: github-mcp
    allow:
      - "session:*"        # MCP transport handshake — required to connect
      - "notify:*"
      - tools:list
      - resources:list
      - "call:get_*"        # reads flow through
      - "call:list_*"
      - "call:search_*"
      - call:add_issue_comment
      - call:create_issue
    require_approval:
      - call:create_pull_request
      - "call:merge_*"      # merges wait for your tap
      - "call:update_*"
      - call:create_or_update_file
    deny:
      - "call:delete_*"     # never, unattended
      - "call:*_workflow"   # no CI dispatch
budget:
  max_actions_per_hour: 200   # a runaway loop can't burn the whole hour
```

Sanity-check it before you rely on it:

```bash
grenz policy check
```

Reads run without interruption; a merge or a file write blocks for a human; a
delete or a workflow dispatch is refused outright. Adjust the lists to your
agent's job — the point is that *you* decide, not the model.

## 4. Wire up Relay for phone approvals (1 min)

This is the step that makes approvals work on a headless box. Add a `relay`
block to `grenz.yaml`:

```yaml
relay:
  url: https://relay.grenz.dev
  poll_window_seconds: 25   # optional; default 25
```

Put the relay token in the vault:

```bash
printf %s "$RELAY_TOKEN" | grenz vault set relay_token
```

Now, when OpenClaw calls a `require_approval` action, the proxy POSTs the
blocked action's metadata — agent, tool, action, target, the same fields a
human approver sees — out to the relay. You get a Slack message with **Approve**
/ **Deny** buttons; your tap comes back to the proxy and settles the request.
The relay holds **no credentials** and makes **no decisions** — only that
metadata leaves the box, never the PAT. If the relay is unreachable, the
approval simply expires and the action is **denied**. See [docs/relay.md](relay.md)
for the full behavior.

> **Why Relay and not the plain Slack webhook?** Both notify you, but only Relay
> carries the *verdict back*. On a machine with no human at the keyboard, a
> notification you can't act on isn't an approval path. When both a relay and a
> Slack webhook are configured, the relay wins.

## 5. Run Grenz

```bash
grenz run
```

On startup you'll see `notify: relay (https://relay.grenz.dev)` — that confirms
approvals will route to your phone rather than a keyboard that isn't there.

## 6. Point OpenClaw at Grenz (30s)

Make the two-line edit to `~/.openclaw/openclaw.json` shown at the top of this
page: swap the GitHub MCP server's `url` to `http://127.0.0.1:8787/u/github-mcp`
and its `Authorization` header to `Bearer <YOUR_GRENZ_TOKEN>` (the token from
step 1). Restart OpenClaw so it reloads the config.

That's the whole integration. OpenClaw still speaks streamable-HTTP MCP to what
looks like the GitHub MCP server; Grenz checks each tool call against your
policy, injects the real PAT only for what it allows, and forwards it.

## 7. Prove the credential is gone

Grenz ships with a scanner for exactly the file you just changed. Point it at
OpenClaw's config:

```bash
grenz scan ~/.openclaw/openclaw.json
```

Before you made the swap, this flags the plaintext `ghp_…` an infostealer would
harvest (and exits non-zero). After the swap it finds nothing to take — the only
secret left in the file is the `GRENZ_TOKEN`, which does nothing off your
loopback and can be revoked in one command.

Then watch the guardrail fire. Ask OpenClaw to do something that needs approval —
"merge PR #4 in acme/app". The tool call **blocks**, a Slack message hits your
phone, and the merge only happens if you tap **Approve** (or expires and is
denied if you don't). Ask it to delete a file and it's refused before the request
ever leaves your machine.

Watch all of it live if you like:

```bash
cd console && bun install && bun run dev     # → http://localhost:4180
```

Every decision shows up with its reason, and no credential material appears
anywhere in it.

---

## What you built

- OpenClaw holds only a `GRENZ_TOKEN`. Your GitHub PAT lives in the proxy's
  encrypted vault and is injected only on allowed, outbound requests — so
  `openclaw.json` is no longer a credential an infostealer can cash.
- Reads flow through untouched; merges and writes need your tap; deletes and CI
  dispatch are denied by default.
- Because the box is headless, approvals reach your phone through Relay — so a
  24/7 agent can still ask permission for the one action in a hundred that
  warrants it.
- `grenz revoke openclaw` cuts the agent off instantly, everywhere the proxy
  serves it — and since it never held the PAT, there's no secret to rotate
  afterward.

## Notes and next steps

- **Other tools, same shape.** OpenClaw's Slack, Linear, or any other
  streamable-HTTP MCP server wraps the same way: add an `upstreams:` entry,
  vault its credential, point OpenClaw's `url` at `/u/<name>` with the
  `GRENZ_TOKEN`. See the [general MCP quickstart](quickstart.md).
- **Local (stdio) MCP servers.** Grenz fronts a network endpoint, not a
  subprocess — it can't sit in front of a `command`-based stdio MCP server. Use
  the server's HTTP/remote variant (as with the GitHub MCP server here) so
  there's an endpoint to point at the proxy.
- **The approval clock.** A held connection tops out around Bun's ~255s socket
  ceiling, but Relay long-polls in short windows and reconnects until the
  approval's full TTL (5 min) — so a slow tap doesn't drop the request.
- **Tighten from real traffic.** After OpenClaw has run for a while, let its own
  usage write a tighter policy: `grenz policy shrinkwrap` proposes dropping the
  grants it never used. See [docs/quickstart.md](quickstart.md#tighten-a-broad-policy-from-real-usage-shrinkwrap).

> Grenz is **pre-action permissioning** — it decides whether an action may
> happen, before it happens. The local decision log is plain, truncatable
> operational visibility, not an audit trail; Grenz makes no tamper-evidence or
> compliance claims.
