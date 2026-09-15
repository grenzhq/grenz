/**
 * Builds the prompt for `grenz suggest`. Pure and synchronous — no network,
 * no IO. Grounds the model in the REAL action vocabulary each configured
 * upstream can produce (reusing the same adapters/vocabulary.ts the
 * Blast-Radius Analyzer and policy linter already use) so it cannot invent
 * action names that don't exist, and includes the CURRENT policy so it edits/
 * extends rather than replacing it wholesale.
 */

export interface UpstreamVocabulary {
  readonly type: string;
  readonly actions: readonly string[] | null; // null = not enumerable (generic mcp)
}

export interface PromptInput {
  readonly intent: string;
  readonly currentPolicyYaml: string;
  readonly vocabularyByUpstream: Readonly<Record<string, UpstreamVocabulary>>;
}

export function buildPrompt(input: PromptInput): string {
  const lines: string[] = [
    "You are drafting a Grenz policy.yaml — an access-control policy for an AI agent.",
    "",
    "SHAPE (respond with ONLY a document matching this shape, no prose, no markdown fences):",
    "  agent: <string>            # agent id, keep the existing value unless asked to change it",
    "  on_behalf_of: <string>     # human owner, keep the existing value unless asked to change it",
    "  grants:",
    "    - tool: <upstream name>  # must match one of the configured upstream names below",
    "      allow: [<action>, ...]",
    "      deny: [<action>, ...]",
    "      require_approval: [<action>, ...]",
    "  budget:                    # optional",
    "    max_actions_per_hour: <number>",
    "",
    "RULES:",
    "  - Precedence is deny > require_approval > allow. Deny-by-default: anything not",
    "    listed under allow/require_approval is already denied — do not add unnecessary denies.",
    "  - Only use action names from the vocabulary given below for each tool. Never invent one.",
    "  - Prefer the narrowest grants that satisfy the intent.",
    "",
    "CURRENT policy.yaml (edit/extend this, do not discard existing grants unless asked):",
    "```",
    input.currentPolicyYaml,
    "```",
    "",
    "CONFIGURED UPSTREAMS AND THEIR VALID ACTIONS:",
  ];
  for (const [name, vocab] of Object.entries(input.vocabularyByUpstream)) {
    if (vocab.actions === null) {
      lines.push(
        `  - ${name} (type: ${vocab.type}): action names are not enumerable — use the literal ` +
          `tool/action names the agent's own requests already use.`,
      );
    } else {
      lines.push(`  - ${name} (type: ${vocab.type}): ${vocab.actions.join(", ")}`);
    }
  }
  lines.push("", "REQUESTED CHANGE:", input.intent);
  return lines.join("\n");
}
