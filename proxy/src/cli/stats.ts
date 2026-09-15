/**
 * `grenz stats` — show the local anonymized aggregate (decision counts per
 * tool/action, last 24h). This is exactly the shape that opt-in telemetry would
 * send: no agent id, no targets, no secrets.
 */
import { grenzPaths } from "../config/paths.ts";
import { RequestLog } from "../log/request-log.ts";
import { homeFlag, type ParsedArgs } from "./args.ts";

const WINDOW_MS = 24 * 60 * 60 * 1000;

export async function runStats(args: ParsedArgs): Promise<number> {
  const paths = grenzPaths(homeFlag(args));
  if (!(await Bun.file(paths.db).exists())) {
    process.stdout.write("no request log yet — start the proxy with `grenz run`\n");
    return 0;
  }
  const log = new RequestLog(paths.db);
  const rows = log.aggregate(Date.now() - WINDOW_MS);
  log.close();

  if (rows.length === 0) {
    process.stdout.write("no requests in the last 24h\n");
    return 0;
  }
  process.stdout.write("last 24h — decisions by tool:action (anonymized aggregate)\n");
  process.stdout.write("  tool         action                allow  deny  approval\n");
  for (const r of rows) {
    process.stdout.write(
      `  ${r.tool.padEnd(12)} ${r.action.padEnd(21)} ${String(r.allow).padStart(5)} ${String(r.deny).padStart(5)} ${String(r.require_approval).padStart(9)}\n`,
    );
  }
  return 0;
}
