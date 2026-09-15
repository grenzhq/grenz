/**
 * Load + validate config and policy from a Grenz home directory.
 *
 * Fails closed: a missing or malformed config/policy produces a structured
 * `ConfigError` that the CLI turns into a non-zero exit (for `run`, the proxy
 * refuses to start rather than serving with an unknown policy).
 */
import { parse as parseYaml } from "yaml";
import { isAbsolute, join } from "node:path";
import { configSchema, type GrenzConfig } from "./schema.ts";
import { compilePolicyYaml, type CompiledPolicy } from "../policy/compile.ts";
import { grenzPaths, type GrenzPaths } from "./paths.ts";
import type { ProfileEntry } from "../policy/profile-entry.ts";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export interface LoadedConfig {
  readonly paths: GrenzPaths;
  readonly config: GrenzConfig;
  readonly policy: CompiledPolicy;
  /** Raw profile entries from local files (name-only declarations contribute
   *  none — content arrives via the signed bundle). The store owns the merge. */
  readonly entries: readonly ProfileEntry[];
}

async function readTextOrThrow(path: string, what: string): Promise<string> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    throw new ConfigError(`${what} not found at ${path} — run \`grenz init\` first`);
  }
  return file.text();
}

export async function loadConfig(explicitHome?: string): Promise<GrenzConfig> {
  const paths = grenzPaths(explicitHome);
  const text = await readTextOrThrow(paths.config, "grenz.yaml");

  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (err) {
    throw new ConfigError(`invalid grenz.yaml: ${err instanceof Error ? err.message : String(err)}`);
  }

  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? ` at \`${first.path.join(".")}\`` : "";
    throw new ConfigError(`invalid grenz.yaml${where}: ${first ? first.message : "validation failed"}`);
  }
  return parsed.data;
}

export async function loadPolicy(explicitHome?: string): Promise<CompiledPolicy> {
  const paths = grenzPaths(explicitHome);
  const text = await readTextOrThrow(paths.policy, "policy.yaml");
  const result = compilePolicyYaml(text);
  if (!result.ok) {
    throw new ConfigError(result.error);
  }
  return result.policy;
}

/**
 * Read and compile-validate each named profile that declares a local `file`,
 * returning its RAW policy YAML text as a `ProfileEntry`. A name-only
 * declaration (no `file:` — its content arrives via the Slice 3 signed
 * bundle) contributes no entry and does not throw. loadProfiles no longer
 * merges — the store owns the merge now.
 *
 * A profile source `file` is a LOCAL FILE PATH, resolved against the Grenz
 * home unless absolute. A missing or uncompilable file throws ConfigError —
 * the proxy refuses to start (fail closed), exactly like a malformed default
 * policy.
 *
 * A profile file is authored as a normal policy YAML (it requires the same
 * `agent:`/`on_behalf_of:` headers as any policy.yaml); compiling it here is
 * validation only — the store extracts and merges grants at use time.
 */
export async function loadProfiles(paths: GrenzPaths, config: GrenzConfig): Promise<readonly ProfileEntry[]> {
  const out: ProfileEntry[] = [];
  for (const [name, src] of Object.entries(config.policy_profiles)) {
    if (src.file === undefined) continue; // name-only: content comes from the bundle
    const filePath = isAbsolute(src.file) ? src.file : join(paths.home, src.file);
    const text = await readTextOrThrow(filePath, `policy profile "${name}"`);
    const result = compilePolicyYaml(text); // validate at load; fail closed like the default
    if (!result.ok) {
      throw new ConfigError(`policy profile "${name}" (${src.file}): ${result.error}`);
    }
    out.push({ name, policy: text });
  }
  return out;
}

export async function loadAll(explicitHome?: string): Promise<LoadedConfig> {
  const paths = grenzPaths(explicitHome);
  const [config, policy] = await Promise.all([loadConfig(explicitHome), loadPolicy(explicitHome)]);
  const entries = await loadProfiles(paths, config);
  return { paths, config, policy, entries };
}
