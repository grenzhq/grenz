/**
 * Pure preflight checks for `grenz doctor`. No IO, no network — every input
 * is gathered by the CLI and passed in, so this whole module is deterministic
 * and table-testable. Details never carry a secret value: credential checks
 * report presence (a boolean) and the vault key NAME only.
 */
import { expiryStatus } from "../config/expiry.ts";
import { BASH_TOOL } from "../adapters/bash.ts";

export type CheckStatus = "ok" | "warn" | "fail";

export interface Check {
  readonly name: string;
  readonly status: CheckStatus;
  readonly detail: string;
}

export interface DoctorInputs {
  readonly configError: string | null;
  readonly upstreams: Readonly<Record<string, { type: string; decoy: boolean; credential: string | null }>>;
  readonly policyError: string | null;
  readonly grantCount: number;
  readonly grantTools: readonly string[];
  readonly vaultError: string | null;
  readonly credentialPresent: Readonly<Record<string, boolean>>;
  readonly adminTokenPresent: boolean;
  /** Configured agents with their resolved absolute expiry (null = never). */
  readonly agents: readonly { readonly id: string; readonly expiresAtMs: number | null }[];
  /** Wall clock at report time, injected so this module stays pure/testable. */
  readonly now: number;
  /** Socket mode state, or null when `listen.socket` is unset (TCP-only). */
  readonly socket: {
    readonly path: string;
    /** Non-null when the configured path is unusable (NUL, relative, too long). */
    readonly pathError: string | null;
    /** Parent-directory permission bits, or null when it does not exist yet. */
    readonly dirMode: number | null;
    /** A socket file with no listener — a previous proxy exited uncleanly. */
    readonly stale: boolean;
  } | null;
  readonly port: number;
  readonly portInUse: boolean;
  readonly integrations: {
    readonly slackWebhook: boolean;
    readonly llmApiKey: boolean;
    /** As CONFIGURED. Whether it can actually run is derived from planeKeys. */
    readonly telemetryEnabled: boolean;
  };
  /**
   * Vault keys that a configured plane block needs before it can do anything.
   *
   * Every one of these degrades SILENTLY at runtime: the proxy prints a line to
   * stderr and carries on with less governance than the config asks for. A
   * preflight tool that reports "all clear" while one of them is missing is
   * telling you the opposite of the truth, so they are checked here.
   */
  readonly planeKeys: readonly {
    readonly block: PlaneBlock;
    readonly key: string;
    readonly present: boolean;
  }[];
}

export type PlaneBlock = "policy_source" | "telemetry" | "relay";

/** What actually happens when the key is absent — the part worth reading. */
const WITHOUT_KEY: Readonly<Record<PlaneBlock, string>> = {
  policy_source: "the proxy serves the local policy.yaml instead, so the plane's policy never applies",
  telemetry: "nothing is reported, so the plane's decision counts stay empty",
  relay: "approvals never reach a human and expire into a refusal",
};

const onoff = (b: boolean): string => (b ? "on" : "off");

export function buildReport(inputs: DoctorInputs): Check[] {
  const checks: Check[] = [];

  // config
  checks.push(
    inputs.configError
      ? { name: "config", status: "fail", detail: inputs.configError }
      : { name: "config", status: "ok", detail: "grenz.yaml loads and validates" },
  );

  // vault
  checks.push(
    inputs.vaultError
      ? { name: "vault", status: "fail", detail: inputs.vaultError }
      : { name: "vault", status: "ok", detail: "identity present, vault decrypts" },
  );

  // policy
  checks.push(
    inputs.policyError
      ? { name: "policy", status: "fail", detail: inputs.policyError }
      : { name: "policy", status: "ok", detail: `policy.yaml compiles (${inputs.grantCount} grants)` },
  );

  // credentials — one per upstream, unless the vault itself failed.
  if (inputs.vaultError) {
    checks.push({ name: "credentials", status: "fail", detail: "vault must decrypt first" });
  } else {
    for (const [name, up] of Object.entries(inputs.upstreams)) {
      if (up.decoy) {
        checks.push({ name: "credentials", status: "ok", detail: `${name}: decoy (no credential)` });
        continue;
      }
      const present = inputs.credentialPresent[up.credential as string] === true;
      checks.push(
        present
          ? { name: "credentials", status: "ok", detail: `${name}: vault key '${up.credential}' present` }
          : { name: "credentials", status: "fail", detail: `${name}: vault key '${up.credential}' missing or empty` },
      );
    }
  }

  // grants ↔ upstreams (skipped if config or policy failed).
  if (!inputs.configError && !inputs.policyError) {
    // `bash` has no upstream by design: the guard decides and the agent's own
    // shell performs, so there is nothing to forward to. Not an orphan.
    const orphans = inputs.grantTools.filter((t) => t !== BASH_TOOL && !(t in inputs.upstreams));
    if (orphans.length === 0) {
      checks.push({ name: "grants", status: "ok", detail: "every grant maps to a configured upstream" });
    } else {
      for (const t of orphans) {
        checks.push({ name: "grants", status: "warn", detail: `grant for '${t}' matches no configured upstream` });
      }
    }

    // coverage: a REAL upstream with no grant is unreachable — deny-by-default
    // 403s every request to it. This is the classic post-`grenz wrap` trap: the
    // upstream is registered but no policy opens it, so every call fails
    // silently. Decoys are meant to be ungranted, so they are excluded.
    const grantSet = new Set(inputs.grantTools);
    const uncovered = Object.entries(inputs.upstreams)
      .filter(([name, up]) => !up.decoy && !grantSet.has(name))
      .map(([name]) => name);
    if (uncovered.length === 0) {
      checks.push({ name: "coverage", status: "ok", detail: "every upstream has at least one policy grant" });
    } else {
      for (const name of uncovered) {
        checks.push({
          name: "coverage",
          status: "warn",
          detail: `upstream '${name}' has no policy grant — every request to it is denied (deny-by-default); add a grant in policy.yaml`,
        });
      }
    }
  }

  // admin token
  checks.push(
    inputs.adminTokenPresent
      ? { name: "admin token", status: "ok", detail: "present" }
      : { name: "admin token", status: "warn", detail: "missing — created on next grenz run" },
  );

  // agent token expiry — a lapsed primary token reads as lifecycle, not attack.
  // FAIL if already expired, WARN if expiring within the week; silent otherwise.
  // The instant is safe for toISOString() because the schema bounds expiresAtMs.
  for (const agent of inputs.agents) {
    const expiresAtMs = agent.expiresAtMs;
    if (expiresAtMs === null) continue; // never expires — nothing to report
    const iso = new Date(expiresAtMs).toISOString();
    const status = expiryStatus(expiresAtMs, inputs.now);
    if (status === "expired") {
      checks.push({ name: "agent token", status: "fail", detail: `agent '${agent.id}' token expired ${iso} — rotate it` });
    } else if (status === "soon") {
      checks.push({ name: "agent token", status: "warn", detail: `agent '${agent.id}' token expires ${iso}` });
    }
  }

  // socket mode — the 0700 parent directory is what actually restricts reach,
  // so a loose one is a FAIL even though the socket itself binds fine.
  if (inputs.socket !== null) {
    const s = inputs.socket;
    if (s.pathError !== null) {
      checks.push({ name: "socket", status: "fail", detail: s.pathError });
    } else if (s.dirMode !== null && (s.dirMode & 0o077) !== 0) {
      checks.push({
        name: "socket",
        status: "fail",
        detail: `socket directory is mode 0o${s.dirMode.toString(8)} — group/other access must be off`,
      });
    } else if (s.stale) {
      checks.push({
        name: "socket",
        status: "warn",
        detail: `${s.path} has no listener — a previous proxy exited uncleanly; it is removed on next start`,
      });
    } else {
      checks.push({ name: "socket", status: "ok", detail: `agent routes on ${s.path} (your OS user only)` });
    }
  }

  // listen port
  checks.push(
    inputs.portInUse
      ? { name: "port", status: "warn", detail: `port ${inputs.port} in use (another proxy?)` }
      : { name: "port", status: "ok", detail: `port ${inputs.port} free` },
  );

  // plane blocks — configured, but only live if their vault key is there
  if (inputs.planeKeys.length > 0) {
    if (inputs.vaultError) {
      checks.push({ name: "plane", status: "fail", detail: "vault must decrypt first" });
    } else {
      for (const k of inputs.planeKeys) {
        checks.push(
          k.present
            ? { name: "plane", status: "ok", detail: `${k.block}: vault key '${k.key}' present` }
            : {
                name: "plane",
                status: "fail",
                detail: `${k.block}: vault key '${k.key}' missing — ${WITHOUT_KEY[k.block]}`,
              },
        );
      }
    }
  }

  // integrations (informational). Telemetry reports what will actually happen,
  // not what was asked for: "on" with no token in the vault is exactly the lie
  // the `plane` check above exists to stop.
  const telemetryLive =
    inputs.integrations.telemetryEnabled &&
    !inputs.vaultError &&
    inputs.planeKeys.every((k) => k.block !== "telemetry" || k.present);
  checks.push({
    name: "integrations",
    status: "ok",
    detail: `slack ${onoff(inputs.integrations.slackWebhook)} · llm ${onoff(inputs.integrations.llmApiKey)} · telemetry ${onoff(telemetryLive)}`,
  });

  return checks;
}

export function worstStatus(checks: readonly Check[]): CheckStatus {
  let worst: CheckStatus = "ok";
  for (const c of checks) {
    if (c.status === "fail") return "fail";
    if (c.status === "warn") worst = "warn";
  }
  return worst;
}
