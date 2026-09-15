/**
 * `grenz init` — scaffold a Grenz home directory.
 *
 * Creates: an age identity (0600), an empty encrypted vault (0600), a
 * `grenz.yaml` with one GitHub upstream and one agent, and a `policy.yaml`
 * seeded with safe defaults. Mints one GRENZ_TOKEN and prints it exactly once
 * — it is the only secret shown, and it is never written to disk in plaintext.
 */
import { mkdir, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { grenzPaths } from "../config/paths.ts";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { ensureAdminToken } from "../admin/token.ts";
import { generateToken, hashToken } from "../util/token.ts";
import { flagBool, homeFlag, type ParsedArgs } from "./args.ts";

const DEFAULT_AGENT_ID = "claude-code";
const DEFAULT_ON_BEHALF_OF = "you@example.com";

/** The `.gitignore` written into every home. The vault, its age identity, the
 *  admin token, and the local request log are secrets or machine-local state —
 *  they must never be committed. Only the routing config and the policy (which
 *  hold no secret values) are shareable, so they are the sole exceptions. */
export function homeGitignore(): string {
  return `# Grenz home — created by \`grenz init\`. Do NOT commit the secrets in here.
# The age identity, the encrypted vault, the admin token, and the local request
# log are secrets or machine-local state. Only grenz.yaml + policy.yaml (no
# secret values — the token is a hash) are safe to share, so they are un-ignored.
*
!.gitignore
!grenz.yaml
!policy.yaml
!policy.test.yaml
`;
}

/** If the home sits inside a git working tree, return that repo's root — an
 *  agent running in the repo can READ the vault + keys even though `.gitignore`
 *  keeps git from tracking them. Pure filesystem walk; no git invocation. */
export function repoContainingHome(home: string): string | null {
  let dir = home;
  for (;;) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return null; // filesystem root
    dir = parent;
  }
}

function grenzYaml(agentId: string, tokenHash: string): string {
  return `# grenz.yaml — non-secret runtime config.
# Credential VALUES live only in the age vault; this file holds routing + the
# agent's token hash. Safe to commit if you wish (it contains no secrets).

listen:
  host: 127.0.0.1
  port: 8787

upstreams:
  github:
    type: github
    base_url: https://api.github.com
    credential: github_token   # vault key -> set with: grenz vault set github_token
    inject:
      header: Authorization
      scheme: Bearer

  # Example MCP upstream (uncomment + set the credential to use it):
  # linear:
  #   type: mcp
  #   base_url: https://mcp.linear.app/sse
  #   credential: linear_token

agents:
  - id: ${agentId}
    token_hash: ${tokenHash}
`;
}

function policyYaml(agentId: string): string {
  return `# policy.yaml — what "${agentId}" may do. Deny-by-default: anything not
# explicitly allowed is denied. Precedence is deny > require_approval > allow.
agent: ${agentId}
on_behalf_of: ${DEFAULT_ON_BEHALF_OF}   # <- edit to the human this agent acts for

grants:
  - tool: github
    allow:
      - repo:read
      - pr:read
      - pr:create
      - pr:comment
      - issue:read
      - issue:create
    deny:
      - pr:merge
      - repo:delete
      - actions:*
    # require_approval:
    #   - issue:update

  # Matching MCP grant for the example upstream above:
  # - tool: linear
  #   allow:
  #     - session:*
  #     - tools:list
  #     - resources:*
  #     - prompts:*
  #     - notify:*
  #     - call:list_*
  #     - call:get_*
  #   require_approval:
  #     - call:delete_*

budget:
  max_actions_per_hour: 200
`;
}

export async function runInit(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);
  const force = flagBool(args, "force");

  const existing = await Bun.file(paths.config).exists();
  if (existing && !force) {
    process.stderr.write(
      `grenz: already initialized at ${paths.home} (use --force to overwrite config + policy)\n`,
    );
    return 1;
  }

  await mkdir(paths.home, { recursive: true });

  // Age identity — generate only if absent so we never orphan an existing vault.
  const hasIdentity = await Bun.file(paths.identity).exists();
  if (!hasIdentity) {
    const { identity } = await AgeFileCredentialStore.generateIdentity();
    await Bun.write(paths.identity, `${identity}\n`);
    await chmod(paths.identity, 0o600);
  }

  const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  await vault.createEmpty();

  // Admin token for the loopback console/approvals API (0600 local file).
  await ensureAdminToken(paths.adminToken);

  const token = generateToken();
  const tokenHash = await hashToken(token);

  await Bun.write(paths.config, grenzYaml(DEFAULT_AGENT_ID, tokenHash));
  await Bun.write(paths.policy, policyYaml(DEFAULT_AGENT_ID));

  // Keep the vault + keys out of version control. Write only if absent so a
  // user's customized .gitignore is never clobbered on a --force re-init.
  if (!existsSync(paths.gitignore)) {
    await Bun.write(paths.gitignore, homeGitignore());
  }

  process.stdout.write(
    [
      ``,
      `  Grenz initialized at ${paths.home}`,
      ``,
      `  Your GRENZ_TOKEN (shown once — copy it now):`,
      ``,
      `      ${token}`,
      ``,
      `  Next steps:`,
      `    1. Store the real upstream credential in the vault:`,
      `         printf %s "$GITHUB_TOKEN" | grenz vault set github_token`,
      `    2. Start the proxy:`,
      `         grenz run`,
      `    3. Point your agent at Grenz using the token above, e.g.:`,
      `         GitHub base URL -> http://127.0.0.1:8787/u/github`,
      `         Authorization   -> Bearer ${"<GRENZ_TOKEN>"}`,
      ``,
      `  Approvals: actions under \`require_approval\` block until you run`,
      `    \`grenz approve <id>\` (or deny). Optional Slack push:`,
      `         printf %s "$SLACK_WEBHOOK_URL" | grenz vault set slack_webhook`,
      ``,
      `  Edit ${paths.policy} to change what the agent may do.`,
      ``,
    ].join("\n") + "\n",
  );

  // The home holds the vault + age identity + admin token. If it sits inside a
  // git repo the agent works in, the agent can read those secrets directly —
  // `.gitignore` stops a commit, not a read. Steer toward a home outside the
  // worktree (a global `GRENZ_HOME`) for agents you don't fully trust.
  const repoRoot = repoContainingHome(paths.home);
  if (repoRoot !== null) {
    process.stderr.write(
      [
        ``,
        `  ⚠ This Grenz home is inside a git repository:`,
        `      ${repoRoot}`,
        `    A .gitignore was written so its vault + keys are not committed — but an`,
        `    agent running in this repo can still READ them. For agents you don't`,
        `    fully trust, keep the home OUTSIDE their worktree:`,
        `        export GRENZ_HOME="$HOME/.grenz" && grenz init`,
        ``,
      ].join("\n") + "\n",
    );
  }

  return 0;
}
