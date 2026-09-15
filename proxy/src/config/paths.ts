/**
 * Resolve the Grenz home directory and the paths of everything inside it.
 *
 * Precedence for the home dir: explicit `--home` > `GRENZ_HOME` env >
 * `./.grenz`. Everything Grenz persists lives under this one directory.
 */
import { resolve, join } from "node:path";

export interface GrenzPaths {
  readonly home: string;
  readonly gitignore: string; // .gitignore (keeps the vault + keys out of version control)
  readonly config: string; // grenz.yaml
  readonly policy: string; // policy.yaml
  readonly policyTests: string; // policy.test.yaml (assertions for `grenz policy test`)
  readonly identity: string; // age secret key
  readonly vault: string; // age-encrypted credential file
  readonly db: string; // requests.db
  readonly adminToken: string; // admin.token (loopback console/admin API, bootstrap admin)
  readonly adminTokens: string; // admin-tokens.json (named RBAC operator tokens)
  readonly revocations: string; // revocations.json (kill-switch: cut-off agents)
  readonly fleetRevocations: string; // fleet-revocations.json (signed fleet kill-set cache + its floor)
  readonly delegations: string; // delegations.json (attenuated sub-tokens)
  readonly grants: string; // grants.json (just-in-time temporary widenings)
  readonly breakGlass: string; // break-glass.json (emergency unlock windows)
  readonly policySuggested: string; // policy.suggested.yaml (grenz suggest output — never auto-applied)
  readonly policyHistory: string; // policy-history/ (past policy.yaml versions — convenience, truncatable)
  readonly policyVersion: string; // policy-version.json (persisted anti-rollback floor for signed distribution)
  readonly lastSignedVersion: string; // last-signed-version (signer-side: last version `policy sign` minted from this home)
}

export function resolveHome(explicit?: string): string {
  const chosen = explicit ?? Bun.env.GRENZ_HOME ?? ".grenz";
  return resolve(chosen);
}

export function grenzPaths(explicitHome?: string): GrenzPaths {
  const home = resolveHome(explicitHome);
  return {
    home,
    gitignore: join(home, ".gitignore"),
    config: join(home, "grenz.yaml"),
    policy: join(home, "policy.yaml"),
    policyTests: join(home, "policy.test.yaml"),
    identity: join(home, "identity"),
    vault: join(home, "vault.age"),
    db: join(home, "requests.db"),
    adminToken: join(home, "admin.token"),
    adminTokens: join(home, "admin-tokens.json"),
    revocations: join(home, "revocations.json"),
    fleetRevocations: join(home, "fleet-revocations.json"),
    delegations: join(home, "delegations.json"),
    grants: join(home, "grants.json"),
    breakGlass: join(home, "break-glass.json"),
    policySuggested: join(home, "policy.suggested.yaml"),
    policyHistory: join(home, "policy-history"),
    policyVersion: join(home, "policy-version.json"),
    lastSignedVersion: join(home, "last-signed-version"),
  };
}
