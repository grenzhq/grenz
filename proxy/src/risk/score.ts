/**
 * Agent risk scoring — the first "SOC for agents" signal.
 *
 * Pure and explainable: given an agent's recent activity (from the request log),
 * produce a 0–100 score, a level, and human-readable reasons. A spike in denials
 * is the strongest signal of a compromised or prompt-injected agent; breadth of
 * distinct denied actions (probing) and a high denial rate reinforce it.
 */

export type RiskLevel = "low" | "elevated" | "high";

export interface AgentActivity {
  readonly total: number;
  readonly allow: number;
  readonly deny: number;
  readonly require_approval: number;
  /** Distinct actions that were DENIED (breadth of probing). */
  readonly distinctDenied: number;
}

export interface RiskAssessment {
  readonly score: number; // 0..100
  readonly level: RiskLevel;
  readonly reasons: readonly string[];
}

const ELEVATED_AT = 25;
const HIGH_AT = 60;

/** Score an agent's recent activity. Pure — same input, same output. */
export function scoreRisk(a: AgentActivity): RiskAssessment {
  const reasons: string[] = [];
  let score = 0;

  // Denials are the primary signal.
  if (a.deny > 0) {
    score += Math.min(a.deny * 4, 60);
    if (a.deny >= 3) reasons.push(`${a.deny} denials`);
  }

  // A high denial RATE (with enough volume) suggests probing / compromise.
  const rate = a.total > 0 ? a.deny / a.total : 0;
  if (a.total >= 5 && rate >= 0.4) {
    score += 20;
    reasons.push(`${Math.round(rate * 100)}% deny rate`);
  }

  // Breadth: many DISTINCT forbidden actions = poking at the fence.
  if (a.distinctDenied >= 3) {
    score += a.distinctDenied * 5;
    reasons.push(`${a.distinctDenied} distinct denied actions`);
  }

  score = Math.min(score, 100);
  const level: RiskLevel = score >= HIGH_AT ? "high" : score >= ELEVATED_AT ? "elevated" : "low";
  return { score, level, reasons };
}
