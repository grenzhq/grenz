/**
 * `grenz risk` — the first "SOC for agents" signal. Scores each agent's recent
 * activity (denial spikes, deny rate, breadth of denied actions) from the local
 * request log. A rising score is your earliest sign of a compromised or
 * prompt-injected agent.
 */
import { loadConfig, ConfigError } from "../config/load.ts";
import { grenzPaths } from "../config/paths.ts";
import { RequestLog } from "../log/request-log.ts";
import { scoreRisk } from "../risk/score.ts";
import { flagString, homeFlag, type ParsedArgs } from "./args.ts";

export async function runRisk(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);
  const paths = grenzPaths(home);

  let config;
  try {
    config = await loadConfig(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  if (!(await Bun.file(paths.db).exists())) {
    process.stdout.write("no request log yet — start the proxy with `grenz run`\n");
    return 0;
  }

  const windowMin = Number(flagString(args, "window") ?? 15);
  const windowMs = (Number.isFinite(windowMin) && windowMin > 0 ? windowMin : 15) * 60_000;
  const since = Date.now() - windowMs;

  const log = new RequestLog(paths.db);
  const lines: string[] = [`agent risk — last ${Math.round(windowMs / 60_000)}m`];
  for (const agent of config.agents) {
    const activity = log.agentActivity(agent.id, since);
    const r = scoreRisk(activity);
    const why = r.reasons.length > 0 ? ` — ${r.reasons.join(", ")}` : "";
    lines.push(
      `  ${agent.id.padEnd(14)} [${r.level.padEnd(8)}] score ${String(r.score).padStart(3)}  ` +
        `(${activity.total} req, ${activity.deny} deny)${why}`,
    );
  }
  log.close();
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
