/**
 * `grenz agent create <id> [--actions <a,b>] [--targets <glob,glob>]`
 *
 * Mint a first-class agent from the terminal: it gets its own GRENZ_TOKEN, is
 * persisted to grenz.yaml, and — because the mint goes through the running
 * proxy's admin API — authenticates immediately, no restart. `--actions` and
 * `--targets` confine the new token on each axis (out-of-scope hits deny with
 * `agent_action_scope` / `agent_target_scope`); omit both for an unrestricted
 * agent that can do everything the shared policy grants.
 *
 * Requires a running `grenz run` (the mint registers the agent live). The raw
 * token is printed exactly once — hand it to the agent as GRENZ_TOKEN. It is
 * never logged; only its hash is stored.
 */
import { adminClient, callAdmin } from "./admin-client.ts";
import { flagString, type ParsedArgs } from "./args.ts";

const USAGE =
  "grenz: usage: grenz agent create <id> [--policy <name>] [--actions <a,b>] [--targets <glob,glob>]\n";

/** Split a comma flag into a trimmed, non-empty list (or undefined if none). */
function listFlag(args: ParsedArgs, name: string): string[] | undefined {
  const raw = flagString(args, name);
  if (!raw || raw.trim().length === 0) return undefined;
  const list = raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
  return list.length > 0 ? list : undefined;
}

export async function runAgent(args: ParsedArgs): Promise<number> {
  const sub = args.positionals[0];
  const id = args.positionals[1];
  if (sub !== "create" || !id) {
    process.stderr.write(USAGE);
    return 1;
  }

  const client = await adminClient(args);
  if (typeof client === "number") return client;

  const body: { id: string; policy?: string; actions?: string[]; targets?: string[] } = { id };
  const policy = flagString(args, "policy");
  if (policy && policy.trim().length > 0) body.policy = policy.trim();
  const actions = listFlag(args, "actions");
  if (actions) body.actions = actions;
  const targets = listFlag(args, "targets");
  if (targets) body.targets = targets;

  const res = await callAdmin(client, "POST", "/console/agents", { body });
  if (!res) return 1;
  if (res.status !== 201) {
    const err = (res.body as { error?: string }).error ?? `http ${res.status}`;
    process.stderr.write(`grenz: could not create agent: ${err}\n`);
    return 1;
  }

  const out = res.body as { id: string; token: string; policy?: string; actions?: string[]; targets?: string[] };
  const scopeBits: string[] = [];
  if (out.policy) scopeBits.push(`profile ${out.policy}`);
  if (out.actions && out.actions.length > 0) scopeBits.push(`actions ${out.actions.join(", ")}`);
  if (out.targets && out.targets.length > 0) scopeBits.push(`targets ${out.targets.join(", ")}`);
  const scopeLine =
    scopeBits.length > 0
      ? `  scope:   ${scopeBits.join(" · ")}`
      : `  scope:   unrestricted (no --actions/--targets given)`;
  process.stdout.write(
    [
      ``,
      `  Agent ${out.id} created`,
      scopeLine,
      ``,
      `  Token (shown once — hand it to the agent as GRENZ_TOKEN):`,
      ``,
      `      ${out.token}`,
      ``,
      `  It authenticates immediately — no restart. Tighten or widen its reach`,
      `  later by editing this agent's \`actions:\`/\`targets:\` in grenz.yaml.`,
      ``,
    ].join("\n") + "\n",
  );
  return 0;
}
