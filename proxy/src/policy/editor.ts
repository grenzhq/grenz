/**
 * Policy editor — the safe bridge between a form and the YAML source.
 *
 * The console lets an operator edit an agent's grants without hand-writing YAML.
 * Two pure functions do the work, and neither one decides anything: they read
 * and rewrite the SOURCE object, and the caller validates the result through the
 * same `compilePolicyYaml` every other policy path uses (deny-by-default: a
 * proposal that does not compile is never written).
 *
 * The governing safety rule is round-tripping the WHOLE parsed object. We only
 * ever touch `.grants`; `budget`, `schedule`, `flows`, `pins`, `tripwires`,
 * `responses`, `first_use`, `decoys`, and anything else stay exactly where the
 * source put them. Grant list entries are a union — a plain string action
 * pattern (editable) or a `{action, targets}` object (a target-scoped rule).
 * The object form is carried through untouched so a scoped rule is never
 * flattened or dropped.
 */
import { parse as parseYaml, parseDocument, stringify as stringifyYaml } from "yaml";

/** One grant as the editor sees it. Lists hold string patterns and/or the
 *  target-scoped object form; both survive a round-trip. */
export interface EditorGrant {
  readonly tool: string;
  readonly allow: ReadonlyArray<string | Record<string, unknown>>;
  readonly require_approval: ReadonlyArray<string | Record<string, unknown>>;
  readonly deny: ReadonlyArray<string | Record<string, unknown>>;
}

export interface PolicyEditorView {
  readonly grants: EditorGrant[];
  /** Top-level keys other than agent/on_behalf_of/grants — the advanced
   *  sections the editor preserves but does not edit. */
  readonly advancedSections: string[];
}

const TOP_LEVEL_HANDLED = new Set(["agent", "on_behalf_of", "grants"]);

function asEntryList(v: unknown): Array<string | Record<string, unknown>> {
  if (!Array.isArray(v)) return [];
  return v.filter(
    (e): e is string | Record<string, unknown> =>
      typeof e === "string" || (typeof e === "object" && e !== null && !Array.isArray(e)),
  );
}

/**
 * Parse policy source into the editor view. Throws only on a YAML parse failure
 * (the caller maps that to a 400) — a structurally-odd but parseable document
 * yields an empty/partial view rather than throwing.
 */
export function policyEditorView(sourceYaml: string): PolicyEditorView {
  const doc = parseYaml(sourceYaml) as unknown;
  const obj = doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : {};

  const rawGrants = Array.isArray(obj.grants) ? obj.grants : [];
  const grants: EditorGrant[] = rawGrants
    .filter((g): g is Record<string, unknown> => typeof g === "object" && g !== null && !Array.isArray(g))
    .map((g) => ({
      tool: typeof g.tool === "string" ? g.tool : "",
      allow: asEntryList(g.allow),
      require_approval: asEntryList(g.require_approval),
      deny: asEntryList(g.deny),
    }));

  const advancedSections = Object.keys(obj).filter((k) => !TOP_LEVEL_HANDLED.has(k));
  return { grants, advancedSections };
}

/**
 * Produce new policy YAML by replacing ONLY the grants block of the source. The
 * rest of the parsed object — agent, on_behalf_of, and every advanced section —
 * is left byte-for-byte in place, so nothing the editor doesn't understand can
 * be lost. Empty lists are dropped from each grant so the YAML stays clean; a
 * grant keeps its `tool` even when it has no rules. Does NOT validate — the
 * caller compiles the result (fail closed there).
 */
export function writeGrants(sourceYaml: string, grants: ReadonlyArray<EditorGrant>): string {
  const cleaned = grants.map((g) => {
    const out: Record<string, unknown> = { tool: g.tool };
    if (g.allow.length > 0) out.allow = [...g.allow];
    if (g.require_approval.length > 0) out.require_approval = [...g.require_approval];
    if (g.deny.length > 0) out.deny = [...g.deny];
    return out;
  });

  // Edit the source as a Document so comments everywhere OUTSIDE the grants node
  // — an operator's "why" on a budget or tripwire — survive the round-trip. Only
  // the grants node is replaced. A blank/non-map source falls back to a fresh dump.
  const doc = parseDocument(sourceYaml);
  if (doc.contents == null) {
    return stringifyYaml({ grants: cleaned });
  }
  doc.set("grants", doc.createNode(cleaned));
  return doc.toString();
}
