/**
 * `grenz add <tool> --template <name>` and `grenz template list|show`.
 *
 * `add` snaps a bundled policy template into the local config + policy (adding
 * the upstream and its grant), re-validates, and writes. Rewriting the YAML
 * drops comments — that's the tradeoff for machine-managed edits.
 */
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { grenzPaths } from "../config/paths.ts";
import { configSchema } from "../config/schema.ts";
import { compilePolicyObject } from "../policy/compile.ts";
import { templateRegistry, type UpstreamType } from "../registry/templates.ts";
import { applyTemplate } from "../registry/apply.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

const TYPES: readonly UpstreamType[] = ["github", "mcp", "linear", "slack"];

function isUpstreamType(s: string): s is UpstreamType {
  return (TYPES as readonly string[]).includes(s);
}

async function readYaml(path: string, what: string): Promise<Record<string, unknown> | number> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    process.stderr.write(`grenz: ${what} not found at ${path} — run \`grenz init\` first\n`);
    return 1;
  }
  const parsed = parseYaml(await file.text());
  if (parsed === null || typeof parsed !== "object") {
    process.stderr.write(`grenz: ${what} at ${path} is not a mapping\n`);
    return 1;
  }
  return parsed as Record<string, unknown>;
}

export async function runAdd(args: ParsedArgs): Promise<number> {
  const type = args.positionals[0];
  if (!type || !isUpstreamType(type)) {
    process.stderr.write(`grenz: usage: grenz add <${TYPES.join("|")}> --template <name> [--name <upstream>]\n`);
    return 1;
  }
  const templateName = flagString(args, "template");
  if (!templateName) {
    process.stderr.write("grenz: --template <name> is required (see `grenz template list`)\n");
    return 1;
  }
  const template = templateRegistry.get(type, templateName);
  if (!template) {
    process.stderr.write(`grenz: no template "${type}/${templateName}" (see \`grenz template list --tool ${type}\`)\n`);
    return 1;
  }

  const upstreamName = flagString(args, "name") ?? type;
  const credentialKey = `${upstreamName}_token`;
  const paths = grenzPaths(homeFlag(args));

  const configObj = await readYaml(paths.config, "grenz.yaml");
  if (typeof configObj === "number") return configObj;
  const policyObj = await readYaml(paths.policy, "policy.yaml");
  if (typeof policyObj === "number") return policyObj;

  const result = applyTemplate({ configObj, policyObj, upstreamName, credentialKey, template });
  if (!result.ok) {
    process.stderr.write(`grenz: ${result.error}\n`);
    return 1;
  }

  // Fail closed: never write a config/policy that doesn't validate.
  const configCheck = configSchema.safeParse(result.config);
  if (!configCheck.success) {
    process.stderr.write(`grenz: merged grenz.yaml is invalid: ${configCheck.error.issues[0]?.message ?? "?"}\n`);
    return 1;
  }
  const policyCheck = compilePolicyObject(result.policy);
  if (!policyCheck.ok) {
    process.stderr.write(`grenz: merged policy is invalid: ${policyCheck.error}\n`);
    return 1;
  }

  await Bun.write(paths.config, stringifyYaml(result.config));
  await Bun.write(paths.policy, stringifyYaml(result.policy));

  process.stdout.write(
    [
      `Added ${type}/${templateName} (${template.riskTier} risk) as upstream "${upstreamName}".`,
      `  policy: grant for "${upstreamName}" (${template.grant.allow?.length ?? 0} allow, ` +
        `${template.grant.deny?.length ?? 0} deny, ${template.grant.require_approval?.length ?? 0} require_approval)`,
      `  next:   printf %s "$TOKEN" | grenz vault set ${credentialKey}`,
      template.baseUrl.includes("your-") ? `  edit:   set the base_url for "${upstreamName}" in grenz.yaml` : "",
      `  note:   comments in grenz.yaml / policy.yaml were regenerated`,
    ]
      .filter(Boolean)
      .join("\n") + "\n",
  );
  return 0;
}

export function runTemplate(args: ParsedArgs): number {
  const sub = args.positionals[0];
  if (sub === "list") {
    const toolFlag = flagString(args, "tool");
    const filter = toolFlag && isUpstreamType(toolFlag) ? toolFlag : undefined;
    const rows = templateRegistry.list(filter);
    process.stdout.write("templates:\n");
    for (const t of rows) {
      process.stdout.write(`  ${t.type}/${t.name}  [${t.riskTier}]  ${t.description}\n`);
    }
    process.stdout.write(`\nadd one with:  grenz add <tool> --template <name>\n`);
    return 0;
  }
  if (sub === "show") {
    const type = args.positionals[1];
    const name = args.positionals[2];
    if (!type || !isUpstreamType(type) || !name) {
      process.stderr.write("grenz: usage: grenz template show <tool> <name>\n");
      return 1;
    }
    const t = templateRegistry.get(type, name);
    if (!t) {
      process.stderr.write(`grenz: no template "${type}/${name}"\n`);
      return 1;
    }
    process.stdout.write(stringifyYaml({ tool: t.type, base_url: t.baseUrl, ...t.grant }));
    return 0;
  }
  process.stderr.write("grenz: usage: grenz template <list|show>\n");
  return 1;
}
