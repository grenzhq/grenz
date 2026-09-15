"use client";

interface RiskRow {
  agent: string;
  level: string;
  score: number;
  reasons: string[];
}
interface FwEvent {
  id: number;
  agentId: string;
  tool: string;
  action: string;
  defense: { kind: string; label: string };
}
interface ApprovalRow {
  id: string;
  tool: string;
  action: string;
  agentId: string;
}

const SHARP = new Set(["trap", "trifecta", "identity"]);

/** What needs a human's eyes, pulled to the top so it can't get buried under
 *  the feed: a compromised-looking agent, a tripwire that fired, a decision
 *  waiting on you. Calm and reassuring when there's nothing. */
export function AttentionStrip({
  risk,
  firewall,
  approvals,
}: {
  risk: RiskRow[];
  firewall: FwEvent[];
  approvals: ApprovalRow[];
}) {
  const hot = risk.filter((a) => a.level === "high" || a.level === "elevated");
  const trips = firewall.filter((e) => SHARP.has(e.defense.kind)).slice(0, 3);
  const pending = approvals.length;

  if (hot.length === 0 && trips.length === 0 && pending === 0) {
    return (
      <div className="attn calm">
        <span className="attn-dot" />
        All clear — no agent flagged, no defense tripped, nothing waiting on you.
      </div>
    );
  }

  return (
    <div className="attn">
      {trips.map((t) => (
        <a className="attn-card trip" href="/access" key={`t${t.id}`}>
          <span className="attn-tag">Tripwire</span>
          <span className="attn-body">
            <b>{t.agentId}</b> tripped <span className="mono">{t.defense.label}</span> on{" "}
            <span className="mono">
              {t.tool}:{t.action}
            </span>
          </span>
        </a>
      ))}
      {hot.map((a) => (
        <a className={`attn-card ${a.level === "high" ? "trip" : "warn"}`} href="/access" key={`r${a.agent}`}>
          <span className="attn-tag">{a.level} risk</span>
          <span className="attn-body">
            <b>{a.agent}</b> · score {a.score}
            {a.reasons[0] ? <span className="attn-why"> · {a.reasons[0]}</span> : null}
          </span>
        </a>
      ))}
      {pending > 0 && (
        <a className="attn-card wait" href="#pending-approvals">
          <span className="attn-tag">Waiting</span>
          <span className="attn-body">
            <b>{pending}</b> approval{pending > 1 ? "s" : ""} need your decision
          </span>
        </a>
      )}
    </div>
  );
}
