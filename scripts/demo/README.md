# Grenz demos

## `grenz demo-cascade` — one tripped decoy kills the whole swarm

The built-in one-command demo of the thing no other proxy does: a lead agent
spawns two sub-agents, each with its own scoped sub-token; one sub-agent is
raided and reaches for a honeytoken, and the **entire tree** — the lead and
every sibling — is revoked at once, in well under a second.

```
grenz demo-cascade
```

Output:

```
  WHO           DOES                     DECISION WHY
  -- the swarm is working normally --
  lead          read a repo              allow
  reviewer      read a repo              allow
  test-runner   read a repo              allow
  -- the test-runner is raided; it reaches for the honeytoken --
  test-runner   grab the honeytoken      deny   no_matching_allow
  -- one trip. now the ENTIRE tree is dead --
  test-runner   try anything             deny   token_revoked
  reviewer      try anything             deny   token_revoked
  lead          try anything             deny   token_revoked
```

The reviewer and the lead never misbehaved. But one sub-agent touching the decoy
revokes the **root**, and every token in the tree checks the root at the door —
so the whole swarm is cut off together. Runs in-process; no real credentials;
nothing is left on disk.

## `firewall-demo.sh` — watch Grenz stop a rogue agent

A ~10-second, self-contained live demo. It spins up a throwaway Grenz on
loopback with a realistic policy and drives a sequence of requests from a single
agent token, printing the firewall's decision for each.

```
bash scripts/demo/firewall-demo.sh
```

Output:

```
  WHAT THE AGENT TRIES                DECISION  WHY
  read a repo (legit work)       allow
  merge a PR (policy says no)    deny   explicit_deny
  grab the honeytoken            deny   no_matching_allow
  ...then anything at all        deny   token_revoked
  -- operator restores the agent --
  delete the repo (tripwire)     deny   tripwire
  ...then anything at all        deny   token_revoked
```

What it shows, in order:

1. **Legit work is allowed** — `repo:read` passes.
2. **Policy blocks the dangerous write** — `pr:merge` is denied by rule.
3. **The honeytoken is a trap** — touching the decoy upstream is denied and looks
   like an ordinary `no_matching_allow` (the wire is masked so an attacker can't
   tell a trap from a typo), but under the hood the agent's token is revoked…
4. …so **anything it tries next is cut off** (`token_revoked`).
5. After an operator restores it, **one attempt at a tripwired action**
   (`repo:delete`) revokes it again — the mere attempt is enough.

### No real credentials

The `github` upstream is pointed at a dummy vault value and the decision is read
from the `x-grenz-decision` / `x-grenz-reason` response headers, so nothing needs
to reach a real API. Everything runs on `127.0.0.1`, in a temp home that is
removed on exit.

Requires `bun` (to compile the binary) and `curl`.
