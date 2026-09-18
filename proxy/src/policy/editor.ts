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
import {
  isMap,
  isNode,
  isSeq,
  parse as parseYaml,
  parseDocument,
  stringify as stringifyYaml,
  type Document,
  type YAMLMap,
} from "yaml";

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
  // Edit the source as a Document so comments everywhere OUTSIDE the grants node
  // — an operator's "why" on a budget or tripwire — survive the round-trip. A
  // blank/non-map source falls back to a fresh dump.
  const doc = parseDocument(sourceYaml);
  if (doc.contents == null) {
    return stringifyYaml({ grants: grants.map(cleanGrant) }, EMIT);
  }

  const seq = doc.get("grants", true);
  if (!isSeq(seq)) {
    doc.set("grants", doc.createNode(grants.map(cleanGrant)));
    return doc.toString(EMIT);
  }

  // Comments live on the node objects, not in the values, so a rule that
  // survives an edit must keep the node it arrived on. Rebuilding the grants
  // block from plain values would compile to the same policy but throw away
  // every `# --- git: read + local write ---` in it, and reflow the untouched
  // rules besides (a flow-style `targets: [...]` comes back as a block list).
  const byTool = new Map<string, YAMLMap>();
  for (const item of seq.items) {
    if (!isMap(item)) continue;
    const tool = item.get("tool");
    if (typeof tool === "string" && !byTool.has(tool)) byTool.set(tool, item);
  }

  seq.items = grants.map((g) => {
    const map = byTool.get(g.tool);
    if (map === undefined) return doc.createNode(cleanGrant(g));
    byTool.delete(g.tool);
    for (const key of LIST_KEYS) rewriteList(doc, map, key, g[key]);
    return map;
  });
  return doc.toString(EMIT);
}

/** Emit the way a person writes YAML, so lines nobody edited come back
 *  unchanged: no padding inside `["a", "b"]`, and no wrapping a long list
 *  across seven lines because it passed the default 80-column width. */
const EMIT = { flowCollectionPadding: false, lineWidth: 0 } as const;

const LIST_KEYS = ["allow", "require_approval", "deny"] as const;

function cleanGrant(g: EditorGrant): Record<string, unknown> {
  const out: Record<string, unknown> = { tool: g.tool };
  for (const key of LIST_KEYS) {
    if (g[key].length > 0) out[key] = [...g[key]];
  }
  return out;
}

/**
 * Replace one rule list on an existing grant, reusing the source node for every
 * entry whose value is unchanged. Entries are matched by value, so reordering a
 * list carries each rule's comment along with it.
 */
function rewriteList(
  doc: Document,
  map: YAMLMap,
  key: string,
  entries: ReadonlyArray<string | Record<string, unknown>>,
): void {
  if (entries.length === 0) {
    map.delete(key);
    return;
  }
  const seq = map.get(key, true);
  if (!isSeq(seq)) {
    map.set(key, doc.createNode([...entries]));
    return;
  }
  // A comment before the first entry parses onto the LIST, not onto that entry,
  // so deleting or moving the first rule would strand its header above whatever
  // took its place. Hand it to the entry it was written for.
  const first = seq.items[0];
  if (seq.commentBefore != null && isNode(first) && first.commentBefore == null) {
    first.commentBefore = seq.commentBefore;
    seq.commentBefore = null;
  }

  // A pool rather than a lookup: two identical rules in the source are two
  // nodes with two different comments, and each should be claimed once.
  const pool = new Map<string, unknown[]>();
  for (const item of seq.items) {
    const k = valueKey(isNode(item) ? item.toJSON() : item);
    const bucket = pool.get(k);
    if (bucket) bucket.push(item);
    else pool.set(k, [item]);
  }
  seq.items = entries.map((e) => pool.get(valueKey(e))?.shift() ?? doc.createNode(e));
}

/** Order-independent identity for a rule entry, for matching a proposed entry
 *  against the source node that already holds it. */
function valueKey(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(valueKey).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${valueKey(o[k])}`)
    .join(",")}}`;
}
