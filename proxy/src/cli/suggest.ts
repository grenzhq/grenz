/**
 * `grenz suggest "<intent>"` — draft a candidate policy.yaml from plain
 * English, grounded in the real action vocabulary each configured upstream
 * can produce. Never auto-applied: writes policy.suggested.yaml for review
 * via the existing `grenz policy diff`, which lints and replays it against
 * history before you ever touch the real policy.yaml.
 */
import { loadAll, ConfigError } from "../config/load.ts";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { VaultError } from "../vault/store.ts";
import { actionVocabulary } from "../adapters/vocabulary.ts";
import { buildPrompt, type UpstreamVocabulary } from "../suggest/prompt.ts";
import { AnthropicLlmClient, DEFAULT_MODEL } from "../suggest/llm.ts";
import { validateSuggestion } from "../suggest/response.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

const API_KEY_VAULT_KEY = "llm_api_key";

export async function runSuggest(args: ParsedArgs): Promise<number> {
  const intent = args.positionals[0];
  if (!intent) {
    process.stderr.write('grenz: usage: grenz suggest "<what you want the agent to be able to do>"\n');
    return 1;
  }

  const home = homeFlag(args);
  let loaded;
  try {
    loaded = await loadAll(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const { paths, config } = loaded;

  const vault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  let apiKey: string | undefined;
  try {
    apiKey = await vault.get(API_KEY_VAULT_KEY);
  } catch (err) {
    if (err instanceof VaultError) {
      process.stderr.write(`grenz: vault error (${err.code}): ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  if (!apiKey) {
    process.stderr.write(
      `grenz: no LLM API key found. Try:  printf %s "$ANTHROPIC_API_KEY" | grenz vault set ${API_KEY_VAULT_KEY}\n`,
    );
    return 1;
  }

  const currentPolicyYaml = await Bun.file(paths.policy).text();
  const vocabularyByUpstream: Record<string, UpstreamVocabulary> = {};
  for (const [name, upstream] of Object.entries(config.upstreams)) {
    vocabularyByUpstream[name] = { type: upstream.type, actions: actionVocabulary(upstream.type) };
  }

  const prompt = buildPrompt({ intent, currentPolicyYaml, vocabularyByUpstream });
  const model = flagString(args, "model") ?? DEFAULT_MODEL;
  const client = new AnthropicLlmClient(apiKey, model);

  let raw: string;
  try {
    raw = await client.complete(prompt);
  } catch {
    // Never surface the raw error — keep it generic and actionable.
    process.stderr.write("grenz: the LLM API call failed — check your API key and network connection\n");
    return 1;
  }

  const result = validateSuggestion(raw);
  if (!result.ok) {
    process.stderr.write(`grenz: the suggested policy did not validate: ${result.error}\n`);
    process.stderr.write("grenz: nothing was written\n");
    return 1;
  }

  await Bun.write(paths.policySuggested, result.yaml + "\n");
  process.stdout.write(
    [
      ``,
      `  Wrote ${paths.policySuggested}`,
      ``,
      `  Review exactly what it would change:`,
      `      grenz policy diff ${paths.policySuggested}`,
      ``,
      `  Nothing has been applied — copy it over policy.yaml yourself once you're happy:`,
      `      cp ${paths.policySuggested} ${paths.policy}`,
      ``,
    ].join("\n") + "\n",
  );
  return 0;
}
