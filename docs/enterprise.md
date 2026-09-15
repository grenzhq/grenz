# Grenz Enterprise

Everything in this open-source repo is MIT and stays MIT. Grenz Enterprise is a
small set of features and a hosted service for teams running **headless** agents
— fleets in CI and cron with no human at the keyboard.

## What's in Enterprise

- **IdP-bound agent identity (`grenz login`, OIDC).** Federate operator tokens
  onto your identity provider via an OIDC device flow. Offboard a person and
  their agents' access expires with them — no per-proxy cleanup. This is the one
  feature that lives outside the OSS build; configuring an `sso:` block in the
  OSS binary fails closed with a pointer here.
- **Hosted control plane for headless agents.** An always-on approval queue with
  mobile push (approve from your phone when the launching machine is gone),
  agents bound to your IdP, offboarding-driven revocation, and a hosted CI
  enforcement point so upstream secrets never touch the runner.

## What is NOT Enterprise (free, MIT, forever)

The proxy, the policy engine, deny-by-default enforcement, approvals, the
credential vault (age file **and** HashiCorp Vault backend), tripwires,
break-glass, named admin tokens with roles (RBAC) and quorum, signed policy
distribution, and fleet-wide signed revocation. **If a human is at the keyboard,
Grenz is free.** Nothing in the OSS repo today will ever move behind a paywall.

## Interested?

Email **hello@grenz.dev**.
