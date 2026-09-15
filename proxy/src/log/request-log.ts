/**
 * Local request log — operational visibility ONLY.
 *
 * This is a plain SQLite table. It is NOT tamper-evident and makes no integrity
 * guarantees: it is freely truncatable and that is a feature, not a gap. Its
 * purpose is "what is my agent doing right now", not evidence.
 *
 * By construction there is nowhere to put a secret: the schema has no column for
 * headers, request bodies, tokens, or credential values. The columns that do
 * exist (action, target, reason) are derived only from the request line and the
 * policy source, never from credential material.
 */
import { Database } from "bun:sqlite";
import type { Decision, ReasonCode } from "../policy/types.ts";

export interface LogEntry {
  readonly ts: number; // unix millis
  readonly agentId: string;
  readonly upstream: string;
  readonly tool: string;
  readonly action: string;
  readonly method: string; // protocol op label (HTTP verb / JSON-RPC method)
  readonly target: string; // log-safe target (path or method+tool)
  readonly decision: Decision;
  readonly reason: ReasonCode;
  readonly forwarded: boolean;
  readonly status: number | null; // upstream HTTP status, if forwarded
  /**
   * Billable COST this row represents (for budget accounting). One HTTP request
   * can carry an MCP JSON-RPC batch of several actions, so budget is counted in
   * cost units, not rows; each action costs 1 by default, or its `budget.weights`
   * weight, and a batch bills the sum. Denied / not-forwarded rows are 0.
   */
  readonly count: number;
  /**
   * True when this row was forwarded under `grenz run --shadow` despite the
   * policy verdict being deny/require_approval (observed, not enforced).
   * Absent/false on every enforced row. Operational visibility only.
   */
  readonly shadow?: boolean;
  /**
   * The delegation id when this request was made by a delegated sub-token;
   * null/absent for first-class agents. `agentId` stays the PARENT (the
   * shared-ceiling invariant is unchanged) — this only adds attribution so
   * per-delegation budgets can be counted. Operational visibility only.
   */
  readonly delegationId?: string | null;
}

interface Row {
  ts: number;
  agent_id: string;
  upstream: string;
  tool: string;
  action: string;
  method: string;
  target: string;
  decision: string;
  reason: string;
  forwarded: number;
  status: number | null;
  count: number;
  shadow: number;
  delegation_id: string | null;
}

export class RequestLog {
  private readonly db: Database;

  constructor(path: string) {
    this.db = new Database(path, { create: true });
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS requests (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        INTEGER NOT NULL,
        agent_id  TEXT    NOT NULL,
        upstream  TEXT    NOT NULL,
        tool      TEXT    NOT NULL,
        action    TEXT    NOT NULL,
        method    TEXT    NOT NULL,
        target    TEXT    NOT NULL,
        decision  TEXT    NOT NULL,
        reason    TEXT    NOT NULL,
        forwarded INTEGER NOT NULL,
        status    INTEGER,
        count     INTEGER NOT NULL DEFAULT 1,
        shadow    INTEGER NOT NULL DEFAULT 0,
        delegation_id TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_requests_agent_ts ON requests (agent_id, ts);
      CREATE INDEX IF NOT EXISTS idx_requests_decision ON requests (decision);
      CREATE INDEX IF NOT EXISTS idx_requests_agent_reason ON requests (agent_id, reason, tool, action, ts);
    `);
    // Forward-compat: add the column to a pre-existing table that lacks it.
    const cols = this.db.query<{ name: string }, []>(`PRAGMA table_info(requests)`).all();
    if (!cols.some((c) => c.name === "count")) {
      this.db.exec(`ALTER TABLE requests ADD COLUMN count INTEGER NOT NULL DEFAULT 1`);
    }
    if (!cols.some((c) => c.name === "shadow")) {
      this.db.exec(`ALTER TABLE requests ADD COLUMN shadow INTEGER NOT NULL DEFAULT 0`);
    }
    if (!cols.some((c) => c.name === "delegation_id")) {
      this.db.exec(`ALTER TABLE requests ADD COLUMN delegation_id TEXT`);
    }
  }

  record(entry: LogEntry): void {
    this.db
      .query(
        `INSERT INTO requests
           (ts, agent_id, upstream, tool, action, method, target, decision, reason, forwarded, status, count, shadow, delegation_id)
         VALUES ($ts, $agent, $upstream, $tool, $action, $method, $target, $decision, $reason, $forwarded, $status, $count, $shadow, $delegation)`,
      )
      .run({
        $ts: entry.ts,
        $agent: entry.agentId,
        $upstream: entry.upstream,
        $tool: entry.tool,
        $action: entry.action,
        $method: entry.method,
        $target: entry.target,
        $decision: entry.decision,
        $reason: entry.reason,
        $forwarded: entry.forwarded ? 1 : 0,
        $status: entry.status,
        $count: entry.count,
        $shadow: entry.shadow ? 1 : 0,
        $delegation: entry.delegationId ?? null,
      });
  }

  /**
   * Sum the billable ALLOWED actions for an agent since a timestamp (budget).
   * Sums `count`, not rows, so an MCP batch consumes budget per sub-action.
   */
  countAllowedSince(agentId: string, sinceTs: number): number {
    const row = this.db
      .query<{ n: number }, [string, number]>(
        `SELECT COALESCE(SUM(count), 0) AS n FROM requests
          WHERE agent_id = ? AND decision = 'allow' AND ts >= ?`,
      )
      .get(agentId, sinceTs);
    return row?.n ?? 0;
  }

  /**
   * Same as `countAllowedSince`, but scoped to a single upstream — the input to
   * the per-upstream budget ceiling. Sums `count`, so an MCP batch consumes the
   * per-upstream budget per sub-action, identical to the global budget.
   */
  countAllowedSinceForUpstream(agentId: string, upstream: string, sinceTs: number): number {
    const row = this.db
      .query<{ n: number }, [string, string, number]>(
        `SELECT COALESCE(SUM(count), 0) AS n FROM requests
          WHERE agent_id = ? AND upstream = ? AND decision = 'allow' AND ts >= ?`,
      )
      .get(agentId, upstream, sinceTs);
    return row?.n ?? 0;
  }

  /**
   * Same as `countAllowedSince`, but scoped to ONE delegated sub-token — the
   * input to the per-delegation budget ceiling. No agent filter needed: a
   * delegation id is globally unique and already implies its parent.
   */
  countAllowedSinceForDelegation(delegationId: string, sinceTs: number): number {
    const row = this.db
      .query<{ n: number }, [string, number]>(
        `SELECT COALESCE(SUM(count), 0) AS n FROM requests
          WHERE delegation_id = ? AND decision = 'allow' AND ts >= ?`,
      )
      .get(delegationId, sinceTs);
    return row?.n ?? 0;
  }

  /**
   * Whether this exact (agent, tool, action) has any prior FORWARDED occurrence
   * since a timestamp — the novelty predicate for first-use gating. "Forwarded"
   * (not merely allowed) means it actually reached the upstream, so a shadow row
   * seeds and an upstream_error (allowed but never sent) does not. `sinceTs = 0`
   * asks "as far back as the log reaches". Operational visibility only; a
   * truncated log re-gates.
   */
  hasForwardedActionSince(agentId: string, tool: string, action: string, sinceTs: number): boolean {
    const row = this.db
      .query<{ one: number }, [string, string, string, number]>(
        `SELECT 1 AS one FROM requests
          WHERE agent_id = ? AND tool = ? AND action = ? AND forwarded = 1 AND ts >= ?
          LIMIT 1`,
      )
      .get(agentId, tool, action, sinceTs);
    return row !== null;
  }

  /** Aggregate decision counts since a timestamp, for the console summary. */
  summary(sinceTs: number): {
    total: number;
    allow: number;
    deny: number;
    approvalGranted: number;
    approvalDenied: number;
    approvalExpired: number;
    rememberedGrant: number;
    rememberedDeny: number;
  } {
    const row = this.db
      .query<
        {
          total: number;
          allow: number;
          deny: number;
          approvalGranted: number;
          approvalDenied: number;
          approvalExpired: number;
          rememberedGrant: number;
          rememberedDeny: number;
        },
        [number]
      >(
        `SELECT
           COUNT(*) AS total,
           COALESCE(SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END), 0) AS allow,
           COALESCE(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END), 0) AS deny,
           COALESCE(SUM(CASE WHEN reason = 'approval_granted' THEN 1 ELSE 0 END), 0) AS approvalGranted,
           COALESCE(SUM(CASE WHEN reason = 'approval_denied' THEN 1 ELSE 0 END), 0) AS approvalDenied,
           COALESCE(SUM(CASE WHEN reason = 'approval_expired' THEN 1 ELSE 0 END), 0) AS approvalExpired,
           COALESCE(SUM(CASE WHEN reason = 'approval_remembered_grant' THEN 1 ELSE 0 END), 0) AS rememberedGrant,
           COALESCE(SUM(CASE WHEN reason = 'approval_remembered_deny' THEN 1 ELSE 0 END), 0) AS rememberedDeny
         FROM requests WHERE ts >= ?`,
      )
      .get(sinceTs);
    return (
      row ?? {
        total: 0,
        allow: 0,
        deny: 0,
        approvalGranted: 0,
        approvalDenied: 0,
        approvalExpired: 0,
        rememberedGrant: 0,
        rememberedDeny: 0,
      }
    );
  }

  /**
   * Distinct (tool, action) an agent actually used under a policy `allow`
   * (reason = 'explicit_allow') since a timestamp. The basis for `grenz policy
   * shrinkwrap` — authoring input from operational data, NOT usage evidence.
   * Approval-gated and JIT-grant uses are deliberately excluded so shrinkwrap
   * only ever tightens.
   */
  usedActions(agentId: string, sinceTs: number): Array<{ tool: string; action: string }> {
    return this.db
      .query<{ tool: string; action: string }, [string, number]>(
        `SELECT DISTINCT tool, action FROM requests
          WHERE agent_id = ? AND reason = 'explicit_allow' AND ts >= ?
          ORDER BY tool, action`,
      )
      .all(agentId, sinceTs);
  }

  /**
   * Per-(tool, action) usage evidence for an agent: the last PERMITTED-AND-
   * FORWARDED use (MAX ts) and the row count. The basis for `grenz policy
   * decay`. "Permitted and forwarded" = `forwarded = 1 AND shadow = 0`, which
   * captures explicit_allow AND gated-but-approved (approval_granted/remembered)
   * AND jit_grant — every way Grenz actually performed the action — while
   * excluding shadow observations, upstream errors, and denials. (A
   * response_too_large row also matches: the upstream request WAS forwarded — the
   * action happened — only the oversized body was capped, so counting it is
   * keep-safe.) This is
   * DELIBERATELY broader than shrinkwrap's `usedActions` (`explicit_allow` only):
   * shrinkwrap PROMOTES to `allow` so its narrow basis is a no-promotion guard;
   * decay DEMOTES, so counting every real exercise is keep-safe (more evidence →
   * fewer demotions, never a promotion). Operational visibility ONLY — the
   * ABSENCE of a row is NOT evidence of non-use (the log is freely truncatable).
   */
  lastUsedActions(agentId: string): Array<{ tool: string; action: string; lastTs: number; n: number }> {
    return this.db
      .query<{ tool: string; action: string; lastTs: number; n: number }, [string]>(
        `SELECT tool, action, MAX(ts) AS lastTs, COUNT(*) AS n FROM requests
          WHERE agent_id = ? AND forwarded = 1 AND shadow = 0
          GROUP BY tool, action
          ORDER BY tool, action`,
      )
      .all(agentId);
  }

  /**
   * The earliest observed row — the start of the observation window for `grenz
   * policy decay`. With an `agentId`, scoped to that agent (its first-ever row of
   * ANY decision), which is the honest per-agent window: "we have watched THIS
   * agent since T" — so a renamed or newly-added agent cannot inherit the whole
   * log's age and get its untouched capabilities judged stale. Without one, the
   * global MIN across all agents. null = empty / fully truncated = no coverage. A
   * DELETE of old rows moves this forward, shrinking claimed coverage. Ops only.
   */
  coverageStart(agentId?: string): number | null {
    const row =
      agentId === undefined
        ? this.db.query<{ t: number | null }, []>(`SELECT MIN(ts) AS t FROM requests`).get()
        : this.db
            .query<{ t: number | null }, [string]>(`SELECT MIN(ts) AS t FROM requests WHERE agent_id = ?`)
            .get(agentId);
    return row?.t ?? null;
  }

  /**
   * Anonymized aggregate: decision counts grouped by (tool, action) since a
   * timestamp. This is the ONLY shape that may leave the proxy as opt-in
   * telemetry — it carries no agent id, no target/path, no bodies, no secrets
   * (invariant 5). Ordered deterministically.
   */
  aggregate(sinceTs: number): Array<{
    tool: string;
    action: string;
    allow: number;
    deny: number;
    require_approval: number;
  }> {
    return this.db
      .query<
        { tool: string; action: string; allow: number; deny: number; require_approval: number },
        [number]
      >(
        `SELECT tool, action,
           COALESCE(SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END), 0) AS allow,
           COALESCE(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END), 0) AS deny,
           COALESCE(SUM(CASE WHEN decision = 'require_approval' THEN 1 ELSE 0 END), 0) AS require_approval
         FROM requests WHERE ts >= ?
         GROUP BY tool, action
         ORDER BY tool, action`,
      )
      .all(sinceTs);
  }

  /**
   * Shadow-mode would-block observations grouped by (tool, action, decision)
   * since a timestamp — the requests that a candidate policy WOULD have denied
   * or sent to approval while `--shadow` forwarded them anyway. Only rows with
   * shadow = 1. Ordered deterministically. Operational visibility only.
   */
  shadowWouldBlock(sinceTs: number): Array<{ tool: string; action: string; decision: string; n: number }> {
    return this.db
      .query<{ tool: string; action: string; decision: string; n: number }, [number]>(
        `SELECT tool, action, decision, COUNT(*) AS n
           FROM requests
          WHERE shadow = 1 AND ts >= ?
          GROUP BY tool, action, decision
          ORDER BY tool, action, decision`,
      )
      .all(sinceTs);
  }

  /** Per-agent activity since a timestamp — the input to risk scoring. */
  agentActivity(
    agentId: string,
    sinceTs: number,
  ): { total: number; allow: number; deny: number; require_approval: number; distinctDenied: number } {
    const row = this.db
      .query<
        { total: number; allow: number; deny: number; require_approval: number; distinctDenied: number },
        [string, number]
      >(
        `SELECT
           COUNT(*) AS total,
           COALESCE(SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END), 0) AS allow,
           COALESCE(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END), 0) AS deny,
           COALESCE(SUM(CASE WHEN decision = 'require_approval' THEN 1 ELSE 0 END), 0) AS require_approval,
           COUNT(DISTINCT CASE WHEN decision = 'deny' THEN action END) AS distinctDenied
         FROM requests WHERE agent_id = ? AND ts >= ?`,
      )
      .get(agentId, sinceTs);
    return row ?? { total: 0, allow: 0, deny: 0, require_approval: 0, distinctDenied: 0 };
  }

  /** Most recent entries, newest first. For the CLI/console surface. */
  recent(limit: number): LogEntry[] {
    const rows = this.db
      .query<Row, [number]>(`SELECT * FROM requests ORDER BY id DESC LIMIT ?`)
      .all(limit);
    return rows.map((r) => ({
      ts: r.ts,
      agentId: r.agent_id,
      upstream: r.upstream,
      tool: r.tool,
      action: r.action,
      method: r.method,
      target: r.target,
      decision: r.decision as Decision,
      reason: r.reason as ReasonCode,
      forwarded: r.forwarded === 1,
      status: r.status,
      count: r.count,
      shadow: r.shadow === 1,
      delegationId: r.delegation_id ?? null,
    }));
  }

  /**
   * The most recent entries whose reason is one of `reasons`, newest-first,
   * each carrying its SQLite rowid so callers have a stable, monotonic key.
   * Used by the firewall-activity feed to surface the last N defense events
   * even under a flood of allows. Empty `reasons` returns [] (never a scan).
   */
  recentByReasons(reasons: readonly string[], limit: number): Array<LogEntry & { id: number }> {
    if (reasons.length === 0) return [];
    const placeholders = reasons.map(() => "?").join(",");
    const rows = this.db
      .query<Row & { id: number }, [...string[], number]>(
        `SELECT * FROM requests WHERE reason IN (${placeholders}) ORDER BY id DESC LIMIT ?`,
      )
      .all(...reasons, limit);
    return rows.map((r) => ({
      id: r.id,
      ts: r.ts,
      agentId: r.agent_id,
      upstream: r.upstream,
      tool: r.tool,
      action: r.action,
      method: r.method,
      target: r.target,
      decision: r.decision as Decision,
      reason: r.reason as ReasonCode,
      forwarded: r.forwarded === 1,
      status: r.status,
      count: r.count,
      shadow: r.shadow === 1,
      delegationId: r.delegation_id ?? null,
    }));
  }

  close(): void {
    this.db.close();
  }
}
