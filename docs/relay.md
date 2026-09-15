# Grenz Relay (approval return path for headless runners)

When a `require_approval` rule fires on a headless proxy (CI, cron, a fleet
runner) there is no human at that machine's keyboard to run `grenz approve`.
The **relay** is the outbound-only return path: the proxy POSTs the blocked
action's metadata to a relay you point it at, a human approves from Slack, and
the verdict comes back to the proxy before the approval's TTL expires.

The relay holds **no credentials** and makes **no decisions**. Only approval
metadata (agent id, tool, action, target — the same fields a human approver
sees) leaves the proxy; real credentials never do. If the relay is unreachable,
the approval simply expires and the action is **denied** (deny-by-default).

## Enabling it

1. Add a `relay` block to your config:

   ```yaml
   relay:
     url: https://relay.grenz.dev
     poll_window_seconds: 25   # optional; default 25
   ```

2. Put the relay token in the vault (the value is read from stdin — it never
   appears in a flag or your shell history):

   ```sh
   printf %s "$RELAY_TOKEN" | grenz vault set relay_token
   ```

When both a relay and a Slack webhook are configured, the relay takes
precedence (a headless runner needs the return path). Remove the `relay` block
to fall back to the local Slack/CLI approval path. On startup, `grenz run`
reports `notify: relay (<url>)` when the relay is active.

## How it behaves

- The proxy long-polls the relay in short windows (`poll_window_seconds`) and
  reconnects until a verdict lands or the approval's TTL expires — so a single
  connection never has to be held for the full TTL.
- A returned `approved`/`denied` verdict settles the request locally; the proxy
  is still the sole authority on the clock and the deny.
- A create failure, an unreachable relay, or a malformed verdict never approves
  — the local TTL expires and the action is denied.
- When the request settles by any path (verdict, local expiry, client
  disconnect) the proxy reports the final state back so the relay can close the
  Slack message.
