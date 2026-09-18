/** Shapes the proxy's admin API returns, as the console consumes them. */

export type Decision = "allow" | "deny" | "require_approval";

export interface Summary {
  window_hours: number;
  total: number;
  allow: number;
  deny: number;
  approvalGranted: number;
  approvalDenied: number;
  approvalExpired: number;
  rememberedGrant: number;
  rememberedDeny: number;
  pending: number;
  would_block: Array<{ tool: string; action: string; decision: string; n: number }>;
}

export interface RequestRow {
  ts: number;
  agentId: string;
  upstream: string;
  tool: string;
  action: string;
  method: string;
  target: string;
  decision: Decision;
  reason: string;
  forwarded: boolean;
  status: number | null;
}

export interface Approval {
  id: string;
  agentId: string;
  tool: string;
  action: string;
  target: string;
  expiresAt: number;
}

export interface BroadGrant {
  pattern: string;
  matches: string[];
}

export interface UpstreamExposure {
  upstream: string;
  type: string;
  enumerable: boolean;
  autoAllow: string[];
  requiresApproval: string[];
  broadGrants: BroadGrant[];
  rawPatterns?: { allow: string[]; requireApproval: string[]; deny: string[] };
}

export interface DelegationExposure {
  id: string;
  note: string;
  actions: string[];
  expiresInSeconds: number;
}

export type Severity = "low" | "elevated" | "high";

export interface BlastRadius {
  agent: string;
  severity: Severity;
  upstreams: UpstreamExposure[];
  delegations: DelegationExposure[];
  reasons: string[];
}

export interface AgentBudget {
  agent: string;
  limit: number | null;
  override: boolean;
  spent: number;
  upstreams: Array<{ upstream: string; limit: number; spent: number }>;
}

export interface AgentRisk {
  agent: string;
  level: Severity;
  score: number;
  reasons: string[];
  total: number;
  deny: number;
}

export interface Grant {
  id: string;
  agent: string;
  actions: string[];
  reason: string;
  expires_at: number;
  revoked: boolean;
}

export type DefenseKind = "trap" | "trifecta" | "identity" | "exfil" | "gate" | "rate" | "policy";

export interface FirewallEvent {
  id: number;
  ts: number;
  agentId: string;
  tool: string;
  action: string;
  target: string;
  decision: Decision;
  reason: string;
  forwarded: boolean;
  shadow: boolean;
  occurrences: number;
  defense: { code: string; label: string; kind: DefenseKind; blurb: string; severity: string };
}
