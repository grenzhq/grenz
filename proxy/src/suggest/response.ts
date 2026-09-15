/**
 * Validates a raw LLM response as a compilable policy. NEVER trusts model
 * output blindly: every response must pass the exact same strict Zod
 * validation every hand-written policy already goes through
 * (policy/compile.ts's compilePolicyYaml). Pure and synchronous.
 */
import { compilePolicyYaml } from "../policy/compile.ts";

export type SuggestResult =
  | { readonly ok: true; readonly yaml: string }
  | { readonly ok: false; readonly error: string };

/** Strip a single leading/trailing markdown code fence, if present. */
export function stripCodeFence(text: string): string {
  const trimmed = text.trim();
  const fenced = /^```(?:ya?ml)?\n([\s\S]*?)\n```$/.exec(trimmed);
  return fenced ? fenced[1]! : trimmed;
}

/** Validate a raw LLM response as a compilable policy. */
export function validateSuggestion(rawResponse: string): SuggestResult {
  const yaml = stripCodeFence(rawResponse);
  const compiled = compilePolicyYaml(yaml);
  if (!compiled.ok) {
    return { ok: false, error: compiled.error };
  }
  return { ok: true, yaml };
}
