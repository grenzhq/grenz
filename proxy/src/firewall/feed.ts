/**
 * Firewall-activity feed assembly — pure.
 *
 * Turns raw defense-filtered log rows (newest-first, each with its rowid) into
 * the console's feed events: classify each by its reason code, and coalesce a
 * run of consecutive same-(agent, reason) rows into ONE event with an
 * occurrence count. Coalescing is what keeps the feed legible when a defense
 * fires: a tripwire revokes a token, then every following request from that
 * agent logs `token_revoked` — without coalescing those repeats would flood the
 * cause (the tripwire) right off the top of the feed.
 *
 * Operational visibility over the plain log; no state, no I/O.
 */
import type { Decision } from "../policy/types.ts";
import type { LogEntry } from "../log/request-log.ts";
import { classifyDefense, type DefenseInfo } from "./defenses.ts";

export interface FirewallEvent {
  /** SQLite rowid of the newest row in the run — a stable, monotonic key. */
  readonly id: number;
  readonly ts: number;
  readonly agentId: string;
  readonly tool: string;
  readonly action: string;
  readonly target: string;
  readonly decision: Decision;
  readonly reason: string;
  /**
   * Whether the request was forwarded despite this reason. True under
   * `--shadow` for the behavioural gates (the request was OBSERVED, not
   * blocked), and true for `response_too_large` (the request went upstream; the
   * response was withheld). The console uses this to phrase enforced vs. shadow.
   */
  readonly forwarded: boolean;
  readonly shadow: boolean;
  /** Consecutive same-(agent, reason) rows collapsed into this event. */
  occurrences: number;
  readonly defense: DefenseInfo;
}

export function buildFirewallFeed(
  rows: ReadonlyArray<LogEntry & { id: number }>,
): FirewallEvent[] {
  const events: FirewallEvent[] = [];
  for (const r of rows) {
    const defense = classifyDefense(r.reason);
    if (!defense) continue; // rows arrive pre-filtered; stay closed if one slips
    const last = events[events.length - 1];
    if (last && last.agentId === r.agentId && last.reason === r.reason) {
      last.occurrences += 1;
      continue;
    }
    events.push({
      id: r.id,
      ts: r.ts,
      agentId: r.agentId,
      tool: r.tool,
      action: r.action,
      target: r.target,
      decision: r.decision,
      reason: r.reason,
      forwarded: r.forwarded,
      shadow: r.shadow ?? false,
      occurrences: 1,
      defense,
    });
  }
  return events;
}
