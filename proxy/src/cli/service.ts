/**
 * `grenz service <print|install|uninstall|status>`
 *
 * Keep `grenz run` alive across crashes and reboots by registering it with the
 * OS's own user-scoped supervisor — launchd on macOS, systemd --user on Linux.
 * No root: the unit lives under the user's home and runs as the user. This is
 * the answer to "a foreground `grenz run` dies on logout and takes the fleet
 * with it" — we let the platform supervise, rather than fork a half-daemon.
 *
 *   grenz service print       # show the unit + activation command (writes nothing)
 *   grenz service install     # write the unit and start it (survives reboot)
 *   grenz service uninstall   # stop it and remove the unit
 *   grenz service status      # is it loaded / running?
 *
 * Flags: --name <slug> (default "proxy") distinguishes multiple proxies on one
 * machine; --home selects the GRENZ_HOME the service runs against; --exec
 * overrides the binary path (default: the running grenz binary); --launchd /
 * --systemd force a platform (default: this OS).
 */
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import { homedir } from "node:os";
import { grenzPaths } from "../config/paths.ts";
import { flagString, homeFlag, flagBool, type ParsedArgs } from "./args.ts";
import {
  planService,
  platformFor,
  systemdUnit,
  launchdLabel,
  type ServicePlatform,
  type ServicePlan,
} from "../service/render.ts";

const USAGE = "grenz: usage: grenz service <print|install|uninstall|status> [--name <slug>] [--home <dir>]\n";

/** Sanitize a --name into a safe slug; empty/invalid falls back to "proxy". */
function serviceName(args: ParsedArgs): string {
  const raw = (flagString(args, "name") ?? "proxy").toLowerCase();
  const slug = raw.replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "");
  return slug.length > 0 ? slug : "proxy";
}

/** Which supervisor to target: an explicit flag, else this OS. */
function chosenPlatform(args: ParsedArgs): ServicePlatform | null {
  if (flagBool(args, "launchd")) return "launchd";
  if (flagBool(args, "systemd")) return "systemd";
  return platformFor(process.platform);
}

interface Exec {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}
function sh(cmd: string): Exec {
  const p = Bun.spawnSync(["sh", "-c", cmd]);
  // `Buffer.toString`, not `TextDecoder`: bun-types floats its `@types/node`
  // dependency, and on newer ones a `Buffer` no longer satisfies
  // `TextDecoder.decode`'s parameter type. Buffer's own decode is stable
  // across both and is less code besides.
  return {
    code: p.exitCode,
    stdout: p.stdout.toString("utf8").trim(),
    stderr: p.stderr.toString("utf8").trim(),
  };
}

function buildPlan(args: ParsedArgs, platform: ServicePlatform): ServicePlan {
  const home = grenzPaths(homeFlag(args)).home;
  const execPath = flagString(args, "exec") ?? process.execPath;
  return planService(platform, { name: serviceName(args), execPath, home, userHome: homedir() });
}

export async function runService(args: ParsedArgs): Promise<number> {
  const sub = args.positionals[0];
  if (sub !== "print" && sub !== "install" && sub !== "uninstall" && sub !== "status") {
    process.stderr.write(USAGE);
    return 1;
  }

  const platform = chosenPlatform(args);
  if (!platform) {
    process.stderr.write(
      `grenz: no service integration for platform "${process.platform}" — ` +
        `run \`grenz run\` under your own supervisor (see docs), or pass --launchd/--systemd\n`,
    );
    return 1;
  }
  const plan = buildPlan(args, platform);

  switch (sub) {
    case "print":
      return doPrint(plan);
    case "install":
      return doInstall(args, plan);
    case "uninstall":
      return doUninstall(plan);
    case "status":
      return doStatus(args, platform);
  }
}

function doPrint(plan: ServicePlan): number {
  process.stdout.write(
    [
      `# ${plan.platform} unit for grenz — write to:`,
      `#   ${plan.unitPath}`,
      `# then activate with:`,
      `#   ${plan.activate}`,
      ``,
      plan.content,
    ].join("\n"),
  );
  return 0;
}

function doInstall(args: ParsedArgs, plan: ServicePlan): number {
  // Guide, don't fail: a service pointed at an un-initialized home just crash-
  // loops. Warn loudly but let the operator proceed (they may init next).
  const home = grenzPaths(homeFlag(args)).home;
  if (!existsSync(`${home}/grenz.yaml`)) {
    process.stderr.write(
      `grenz: warning: no grenz.yaml in ${home} — run \`grenz init\` first, or the service will crash-loop\n`,
    );
  }

  try {
    mkdirSync(dirname(plan.unitPath), { recursive: true });
    writeFileSync(plan.unitPath, plan.content, { mode: 0o644 });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`grenz: could not write ${plan.unitPath}: ${msg}\n`);
    return 1;
  }

  const res = sh(plan.activate);
  if (res.code !== 0) {
    // The unit is on disk; only activation failed. Give the operator the exact
    // command to run by hand rather than swallow the error.
    process.stderr.write(
      [
        `grenz: wrote ${plan.unitPath}, but activation failed:`,
        res.stderr || res.stdout || `(exit ${res.code})`,
        `Activate it manually with:`,
        `  ${plan.activate}`,
        ``,
      ].join("\n"),
    );
    return 1;
  }

  process.stdout.write(
    [
      ``,
      `  Grenz service installed and started (${plan.platform}).`,
      `  unit:  ${plan.unitPath}`,
      `  It now starts at login and restarts if it crashes.`,
      ``,
      `  Check it:    grenz service status`,
      `  Remove it:   grenz service uninstall`,
      ``,
    ].join("\n") + "\n",
  );
  return 0;
}

function doUninstall(plan: ServicePlan): number {
  // Best-effort deactivate first (ignore "not loaded"), then remove the file.
  sh(plan.deactivate);
  let removed = false;
  try {
    if (existsSync(plan.unitPath)) {
      rmSync(plan.unitPath);
      removed = true;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`grenz: could not remove ${plan.unitPath}: ${msg}\n`);
    return 1;
  }
  process.stdout.write(
    removed
      ? `Grenz service removed (${plan.unitPath}).\n`
      : `No Grenz service unit at ${plan.unitPath} — nothing to remove.\n`,
  );
  return 0;
}

function doStatus(args: ParsedArgs, platform: ServicePlatform): number {
  const name = serviceName(args);
  if (platform === "launchd") {
    const label = launchdLabel(name);
    const res = sh(`launchctl list "${label}"`);
    if (res.code === 0) {
      process.stdout.write(`${label}: loaded\n${res.stdout}\n`);
      return 0;
    }
    process.stdout.write(`${label}: not loaded\n`);
    return 1;
  }
  const unit = systemdUnit(name);
  const res = sh(`systemctl --user is-active "${unit}.service"; systemctl --user is-enabled "${unit}.service"`);
  process.stdout.write(`${unit}.service: ${res.stdout || "unknown"}\n`);
  return res.stdout.startsWith("active") ? 0 : 1;
}
