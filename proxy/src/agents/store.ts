/**
 * Holds the live set of first-class agents. This is the mutable seam that lets a
 * console-minted agent authenticate immediately, without a `grenz run` restart —
 * the same shape `PolicyStore` uses for hot-reloaded policy. The handler reads
 * `current` per request; the console mint endpoint calls `add()` after the new
 * identity is persisted to grenz.yaml.
 *
 * It never mints or hashes. A duplicate id is REJECTED (fail closed): two agents
 * under one id would make `resolvePrincipal` ambiguous.
 */
import type { AgentConfig } from "../config/schema.ts";

export type AddOutcome = { readonly ok: true } | { readonly ok: false; readonly error: string };

export class AgentStore {
  private agents: readonly AgentConfig[];

  constructor(initial: readonly AgentConfig[]) {
    this.agents = [...initial];
  }

  get current(): readonly AgentConfig[] {
    return this.agents;
  }

  has(id: string): boolean {
    return this.agents.some((a) => a.id === id);
  }

  /** Append a fully-formed agent. Rejects a duplicate id. */
  add(agent: AgentConfig): AddOutcome {
    if (this.has(agent.id)) {
      return { ok: false, error: `agent "${agent.id}" already exists` };
    }
    this.agents = [...this.agents, agent];
    return { ok: true };
  }
}
