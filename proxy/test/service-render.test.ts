import { test, expect, describe } from "bun:test";
import {
  planService,
  platformFor,
  launchdLabel,
  systemdUnit,
  type ServiceSpec,
} from "../src/service/render.ts";

const spec: ServiceSpec = {
  name: "proxy",
  execPath: "/usr/local/bin/grenz",
  home: "/Users/me/.grenz",
  userHome: "/Users/me",
};

describe("platformFor", () => {
  test("maps darwin → launchd, linux → systemd, else null", () => {
    expect(platformFor("darwin")).toBe("launchd");
    expect(platformFor("linux")).toBe("systemd");
    expect(platformFor("win32")).toBeNull();
  });
});

describe("naming", () => {
  test("launchd label + systemd unit are derived from the slug", () => {
    expect(launchdLabel("proxy")).toBe("dev.grenz.proxy");
    expect(systemdUnit("proxy")).toBe("grenz-proxy");
    expect(launchdLabel("ci")).toBe("dev.grenz.ci"); // multi-home distinct
    expect(systemdUnit("ci")).toBe("grenz-ci");
  });
});

describe("planService — launchd", () => {
  const plan = planService("launchd", spec);

  test("writes to the user's LaunchAgents dir with the label filename", () => {
    expect(plan.unitPath).toBe("/Users/me/Library/LaunchAgents/dev.grenz.proxy.plist");
  });
  test("runs `grenz run --home <home>` and keeps it alive across boots", () => {
    expect(plan.content).toContain("<string>/usr/local/bin/grenz</string>");
    expect(plan.content).toContain("<string>run</string>");
    expect(plan.content).toContain("<string>--home</string>");
    expect(plan.content).toContain("<string>/Users/me/.grenz</string>");
    expect(plan.content).toContain("<key>KeepAlive</key>\n  <true/>"); // restart on crash
    expect(plan.content).toContain("<key>RunAtLoad</key>\n  <true/>"); // start at login
  });
  test("logs land in the home", () => {
    expect(plan.content).toContain("/Users/me/.grenz/grenz.out.log");
    expect(plan.content).toContain("/Users/me/.grenz/grenz.err.log");
  });
  test("it is valid-ish plist (declares the header + one dict)", () => {
    expect(plan.content).toContain("<!DOCTYPE plist");
    expect(plan.content).toContain("<plist version=\"1.0\">");
    expect((plan.content.match(/<dict>/g) ?? []).length).toBe(1);
  });
  test("activate loads with -w (enabled), deactivate unloads", () => {
    expect(plan.activate).toContain("launchctl load -w");
    expect(plan.activate).toContain(plan.unitPath);
    expect(plan.deactivate).toContain("launchctl unload");
  });
});

describe("planService — systemd", () => {
  const plan = planService("systemd", spec);

  test("writes to the user systemd dir with the unit filename", () => {
    expect(plan.unitPath).toBe("/Users/me/.config/systemd/user/grenz-proxy.service");
  });
  test("ExecStart runs the binary against the home, restarts always", () => {
    expect(plan.content).toContain('ExecStart="/usr/local/bin/grenz" run --home "/Users/me/.grenz"');
    expect(plan.content).toContain("Restart=always");
    expect(plan.content).toContain("WantedBy=default.target"); // enabled for the user session
  });
  test("activate enables + starts now; deactivate disables + stops now", () => {
    expect(plan.activate).toContain("systemctl --user enable --now");
    expect(plan.activate).toContain("grenz-proxy.service");
    expect(plan.deactivate).toContain("systemctl --user disable --now");
  });
});

describe("path safety", () => {
  test("an `&` in a path is XML-escaped in the plist (never corrupts it)", () => {
    const p = planService("launchd", { ...spec, home: "/Users/me/a&b/.grenz" });
    expect(p.content).toContain("a&amp;b");
    expect(p.content).not.toContain("a&b/"); // the raw ampersand never appears
  });
  test("a space in the binary path survives systemd quoting", () => {
    const p = planService("systemd", { ...spec, execPath: "/opt/my grenz/grenz" });
    expect(p.content).toContain('ExecStart="/opt/my grenz/grenz" run');
  });
});
