/**
 * The proxy's half of device authorization.
 *
 * `grenz connect` with no arguments asks the plane for a pair, prints the short
 * half for a human to type into the console, and polls with the long half until
 * someone approves it. What comes back is a pull token minted for one agent —
 * so nobody ever copies a credential between a browser and a terminal.
 *
 * `fetch` and `sleep` are injected: the poll loop is the part with the
 * interesting behaviour (it has to stop on expiry, survive a flaky network, and
 * never spin), and none of that is testable against a real clock or a real
 * plane.
 */

export interface DeviceStart {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly expiresInSeconds: number;
  readonly intervalSeconds: number;
}

export interface DeviceReady {
  readonly token: string;
  readonly agent: string;
  readonly policyUrl: string;
  readonly statsUrl: string;
}

export type DeviceResult =
  | { readonly ok: true; readonly ready: DeviceReady }
  | { readonly ok: false; readonly error: string };

/** Only what this module calls — a full `typeof fetch` drags in runtime-specific
 *  extras (Bun adds `preconnect`) that a test double has no business providing. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface FlowDeps {
  readonly fetch: FetchLike;
  readonly sleep: (ms: number) => Promise<void>;
  /** Wall clock, injected so a test can expire a flow without waiting. */
  readonly now: () => number;
}

/** Bounds on what the plane may talk us into. A hostile or broken plane must
 *  not be able to make the CLI poll forever or hammer the endpoint. */
const MIN_INTERVAL_SECONDS = 1;
const MAX_INTERVAL_SECONDS = 60;
const MAX_LIFETIME_SECONDS = 1800;
/** Consecutive network failures tolerated before giving up. A proxy is often
 *  being set up on a machine with half-configured networking. */
const MAX_TRANSIENT_FAILURES = 5;

function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, Math.floor(n)));
}

/** Ask the plane to open a device authorization. */
export async function startDeviceFlow(
  plane: string,
  deps: Pick<FlowDeps, "fetch">,
): Promise<{ ok: true; start: DeviceStart } | { ok: false; error: string }> {
  let res: Response;
  try {
    res = await deps.fetch(`${plane}/api/device/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
  } catch {
    return { ok: false, error: `cannot reach ${plane} — check the URL and your network` };
  }
  if (!res.ok) {
    const detail = res.status === 503 ? " (the plane is missing NEXT_PUBLIC_SITE_URL)" : "";
    return { ok: false, error: `the plane refused to start a device flow (${res.status})${detail}` };
  }
  let body: Record<string, unknown>;
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "the plane returned something that is not JSON" };
  }
  const deviceCode = typeof body.device_code === "string" ? body.device_code : "";
  const userCode = typeof body.user_code === "string" ? body.user_code : "";
  const verificationUri = typeof body.verification_uri === "string" ? body.verification_uri : "";
  if (!deviceCode || !userCode || !verificationUri) {
    return { ok: false, error: "the plane's response was missing a device code, a user code, or the link" };
  }
  return {
    ok: true,
    start: {
      deviceCode,
      userCode,
      verificationUri,
      expiresInSeconds: clamp(Number(body.expires_in ?? 900), 30, MAX_LIFETIME_SECONDS),
      intervalSeconds: clamp(Number(body.interval ?? 5), MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS),
    },
  };
}

/**
 * Poll until the code is approved, expires, or the plane says it is gone.
 *
 * Stops on its own deadline as well as the plane's verdict: a plane that
 * answered `pending` forever would otherwise keep a terminal hostage.
 */
export async function pollUntilReady(plane: string, start: DeviceStart, deps: FlowDeps): Promise<DeviceResult> {
  const deadline = deps.now() + start.expiresInSeconds * 1000;
  let interval = start.intervalSeconds * 1000;
  let transientFailures = 0;

  while (deps.now() < deadline) {
    await deps.sleep(interval);

    let res: Response;
    try {
      res = await deps.fetch(`${plane}/api/device/poll`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_code: start.deviceCode }),
      });
    } catch {
      if (++transientFailures > MAX_TRANSIENT_FAILURES) {
        return { ok: false, error: `lost contact with ${plane}` };
      }
      // Back off, but never past the ceiling or the deadline.
      interval = Math.min(interval * 2, MAX_INTERVAL_SECONDS * 1000);
      continue;
    }
    transientFailures = 0;

    let body: Record<string, unknown> = {};
    try {
      body = (await res.json()) as Record<string, unknown>;
    } catch {
      /* fall through on status alone */
    }
    const status = typeof body.status === "string" ? body.status : "";

    if (status === "pending") {
      if (typeof body.interval === "number") {
        interval = clamp(body.interval, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS) * 1000;
      }
      continue;
    }
    if (status === "expired") return { ok: false, error: "the code expired — run `grenz connect` again" };
    if (status === "consumed") return { ok: false, error: "that code was already used — run `grenz connect` again" };
    if (status === "unknown" || res.status === 404) {
      return { ok: false, error: "the plane does not recognize that code — run `grenz connect` again" };
    }
    if (status === "ready") {
      const token = typeof body.token === "string" ? body.token : "";
      const agent = typeof body.agent === "string" ? body.agent : "";
      const policyUrl = typeof body.policy_url === "string" ? body.policy_url : "";
      const statsUrl = typeof body.stats_url === "string" ? body.stats_url : "";
      if (!token || !agent || !policyUrl) {
        return { ok: false, error: "the plane approved the request but sent an incomplete response" };
      }
      return { ok: true, ready: { token, agent, policyUrl, statsUrl } };
    }
    if (!res.ok) return { ok: false, error: `the plane answered ${res.status}` };
  }

  return { ok: false, error: "timed out waiting for approval — run `grenz connect` again" };
}
