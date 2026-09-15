# Security policy

Grenz sits between an agent and real credentials, so a flaw in it can hand an
agent authority it was never granted. We take reports seriously and fix them
first.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
[Report a vulnerability](https://github.com/grenzhq/grenz/security/advisories/new).

Include what you can of:

- the Grenz version (`grenz version`) and platform
- the policy and config needed to reproduce, with credentials removed
- the request or command, what Grenz decided, and what it should have decided

You will get an acknowledgement within 3 working days. We will keep you updated
while we work on a fix, and credit you in the release notes unless you would
rather not be named.

## What counts

In scope, for example:

- a request allowed that the policy denies, or that should have waited for approval
- a real credential reaching an agent, a log line, an error, or an approval payload
- a delegated sub-token reaching beyond its parent's scope
- a shell command passing `grenz hook` that the bash guard documents as refused
- the installer or release artifacts verifying something they should not

Out of scope: what a permitted binary does after it runs (see
[docs/bash-guard.md](docs/bash-guard.md)), attacks that already need your OS user
or the admin token, and quorum approver names, which are self-asserted by design.

## Supported versions

Fixes land on the latest release. Upgrade with the installer in the
[README](README.md#install).
