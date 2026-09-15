/**
 * Render an OS service unit that keeps `grenz run` alive across crashes and
 * reboots — the supervisor Grenz itself deliberately is NOT (a foreground
 * `grenz run` dies on logout/reboot, taking the whole agent fleet with it).
 *
 * We don't reinvent a daemon: we hand the job to the platform's own supervisor,
 * user-scoped so no root is ever needed — launchd on macOS, systemd --user on
 * Linux. Everything here is PURE (no I/O, no env reads): given a spec it returns
 * the unit's path, its content, and the two commands that (de)activate it. The
 * CLI does the writing and the shelling-out.
 */
export type ServicePlatform = "launchd" | "systemd";

export interface ServiceSpec {
  /** Slug distinguishing this proxy from others on the same machine (multi-home).
   *  Sanitized by the caller; used verbatim to build the label/unit name. */
  readonly name: string;
  /** Absolute path to the grenz binary to run (process.execPath at install). */
  readonly execPath: string;
  /** Absolute GRENZ_HOME the proxy runs against. */
  readonly home: string;
  /** The user's home directory (os.homedir()) — where user-scoped units live. */
  readonly userHome: string;
}

export interface ServicePlan {
  readonly platform: ServicePlatform;
  /** Absolute file the unit is written to. */
  readonly unitPath: string;
  /** The unit's full text content. */
  readonly content: string;
  /** Shell command that loads + starts the unit (and re-arms it at boot). */
  readonly activate: string;
  /** Shell command that stops + removes the unit from the supervisor. */
  readonly deactivate: string;
}

/** launchd reverse-DNS label for a proxy named `name`. */
export function launchdLabel(name: string): string {
  return `dev.grenz.${name}`;
}

/** systemd unit basename (no `.service`) for a proxy named `name`. */
export function systemdUnit(name: string): string {
  return `grenz-${name}`;
}

/** Minimal XML text escape for the launchd plist (paths are attacker-distant,
 *  but a `&` or `<` in a path would still corrupt the plist — escape anyway). */
function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function renderLaunchd(spec: ServiceSpec): string {
  const label = launchdLabel(spec.name);
  const args = [spec.execPath, "run", "--home", spec.home];
  const argXml = args.map((a) => `    <string>${xmlEscape(a)}</string>`).join("\n");
  const out = `${spec.home}/grenz.out.log`;
  const err = `${spec.home}/grenz.err.log`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${xmlEscape(label)}</string>
  <key>ProgramArguments</key>
  <array>
${argXml}
  </array>
  <key>WorkingDirectory</key>
  <string>${xmlEscape(spec.home)}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${xmlEscape(out)}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(err)}</string>
</dict>
</plist>
`;
}

function renderSystemd(spec: ServiceSpec): string {
  // Double-quote the paths so a space in the binary path or home survives.
  return `[Unit]
Description=Grenz agent firewall proxy (${spec.name})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="${spec.execPath}" run --home "${spec.home}"
WorkingDirectory=${spec.home}
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
`;
}

/**
 * Build the full install plan for a platform. Pure: the caller supplies the
 * user's home dir in the spec, so nothing here reads the environment.
 */
export function planService(platform: ServicePlatform, spec: ServiceSpec): ServicePlan {
  if (platform === "launchd") {
    const label = launchdLabel(spec.name);
    const unitPath = `${spec.userHome}/Library/LaunchAgents/${label}.plist`;
    return {
      platform,
      unitPath,
      content: renderLaunchd(spec),
      // `load -w` marks it enabled so it also comes back at the next login.
      activate: `launchctl unload "${unitPath}" 2>/dev/null; launchctl load -w "${unitPath}"`,
      deactivate: `launchctl unload -w "${unitPath}"`,
    };
  }
  const unit = systemdUnit(spec.name);
  const unitPath = `${spec.userHome}/.config/systemd/user/${unit}.service`;
  return {
    platform,
    unitPath,
    content: renderSystemd(spec),
    activate: `systemctl --user daemon-reload && systemctl --user enable --now "${unit}.service"`,
    deactivate: `systemctl --user disable --now "${unit}.service"`,
  };
}

/** Map the running OS to its supervisor, or null when unsupported. */
export function platformFor(osPlatform: string): ServicePlatform | null {
  if (osPlatform === "darwin") return "launchd";
  if (osPlatform === "linux") return "systemd";
  return null;
}
