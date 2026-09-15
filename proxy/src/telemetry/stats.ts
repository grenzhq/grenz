/**
 * Opt-in, anonymized policy stats.
 *
 * The ONLY data that may leave the proxy is the aggregate from
 * `RequestLog.aggregate` — decision counts per (tool, action). No agent id, no
 * target/path, no request bodies, no credentials (invariant 5). Reporting is
 * opt-in and behind a `StatsReporter` interface; failures are swallowed so
 * telemetry can never break the proxy.
 */
import type { RequestLog } from "../log/request-log.ts";

export interface StatRow {
  readonly tool: string;
  readonly action: string;
  readonly allow: number;
  readonly deny: number;
  readonly require_approval: number;
}

export interface StatsPayload {
  readonly period_start: number;
  readonly period_end: number;
  readonly rows: StatRow[];
}

/** Build the anonymized aggregate payload for a period. Pure aside from the DB read. */
export function buildPayload(log: RequestLog, periodStart: number, now: number): StatsPayload {
  return { period_start: periodStart, period_end: now, rows: log.aggregate(periodStart) };
}

export interface StatsReporter {
  report(payload: StatsPayload): Promise<void>;
}

/** Default: report nothing (telemetry off). */
export const nullReporter: StatsReporter = {
  async report(): Promise<void> {
    /* opt-out */
  },
};

const REPORT_TIMEOUT_MS = 5000;

export class CloudStatsReporter implements StatsReporter {
  constructor(
    private readonly endpoint: string,
    private readonly orgToken: string,
    private readonly emit: (line: string) => void = () => {},
  ) {}

  async report(payload: StatsPayload): Promise<void> {
    try {
      const res = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.orgToken}`,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(REPORT_TIMEOUT_MS),
      });
      if (!res.ok) this.emit(`[telemetry] stats endpoint returned ${res.status}`);
    } catch {
      // Never surface the error (it could echo the endpoint/token); never throw.
      this.emit("[telemetry] stats report failed (ignored)");
    }
  }
}

/**
 * Decides what each report covers.
 *
 * The reporting window used to be a fixed lookback — `[now - interval, now)` —
 * which is wrong in both directions. A restart re-sends a window the previous
 * process already sent, and a late tick leaves a gap that is never sent. These
 * counts are shown as totals, so a duplicate quietly inflates them.
 *
 * Instead every report covers `[end of the last report, now)`. The clock starts
 * at process start, so decisions from a previous run are not resent: reporting
 * a window once too few beats reporting one twice.
 */
export class StatsWindow {
  private reportedThrough: number;

  constructor(
    private readonly log: RequestLog,
    private readonly reporter: StatsReporter,
    startedAt: number,
  ) {
    this.reportedThrough = startedAt;
  }

  /** Epoch ms the next window starts at. Exposed for tests. */
  get since(): number {
    return this.reportedThrough;
  }

  /**
   * Send the window ending at `now`, or nothing if there were no decisions in
   * it. The window closes either way — an empty stretch has been accounted for.
   */
  async flush(now: number): Promise<StatsPayload | null> {
    const payload = buildPayload(this.log, this.reportedThrough, now);
    this.reportedThrough = now;
    if (payload.rows.length === 0) return null;
    await this.reporter.report(payload);
    return payload;
  }
}
