/**
 * The `grenz policy decay` fleet-evidence file: one proxy's per-agent usage,
 * exported so a peer proxy's decay run can merge it. Operator-internal (the
 * operator already holds the policy + the proxies) — NOT the anonymized telemetry
 * that leaves to the plane. It carries only (tool, action, lastTs, n): no
 * credentials, no targets, no request bodies — the request log has no such
 * columns by construction. Strict Zod at the boundary: an unknown key or a
 * missing field fails closed (the caller refuses to merge).
 */
import { z } from "zod";

/** The largest millisecond value `new Date(ms).toISOString()` can represent
 *  without throwing (ECMAScript time-value range). A file is untrusted input
 *  (it came from another proxy), so any ts is bounded here — an out-of-range
 *  value must FAIL CLOSED at the schema, never crash the report formatter. */
const MAX_TIME_MS = 8_640_000_000_000_000;

/** Printable-ASCII, bounded — these strings are spliced into the stderr report,
 *  so a control character or ANSI escape in a peer file must not forge output. */
const printable = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .regex(/^[\x20-\x7e]+$/, "must be printable ASCII (no control characters)");

export const evidenceActionSchema = z
  .object({
    tool: printable(128),
    action: printable(128),
    /** ms since epoch of the last permitted-and-forwarded use. */
    lastTs: z.number().int().nonnegative().max(MAX_TIME_MS),
    /** row count (informational; shown in the report). */
    n: z.number().int().nonnegative(),
  })
  .strict();

export const evidenceDocSchema = z
  .object({
    /** Whose usage this is; a merge filters on it (no cross-agent veto). */
    agent: printable(128),
    /** Free-text operator label for the proxy this came from (for the report). */
    proxy: printable(64).optional(),
    /** ms since epoch this file was written. */
    generatedAt: z.number().int().nonnegative().max(MAX_TIME_MS),
    actions: z.array(evidenceActionSchema).default([]),
  })
  .strict();

export type EvidenceAction = z.infer<typeof evidenceActionSchema>;
export type EvidenceDoc = z.infer<typeof evidenceDocSchema>;

export function buildEvidenceDoc(
  agent: string,
  proxy: string | undefined,
  generatedAt: number,
  rows: readonly EvidenceAction[],
): EvidenceDoc {
  const actions = rows.map((r) => ({ tool: r.tool, action: r.action, lastTs: r.lastTs, n: r.n }));
  return proxy !== undefined ? { agent, proxy, generatedAt, actions } : { agent, generatedAt, actions };
}

export function serializeEvidenceDoc(doc: EvidenceDoc): string {
  return JSON.stringify(doc, null, 2) + "\n";
}

export type ParseEvidenceResult =
  | { readonly ok: true; readonly doc: EvidenceDoc }
  | { readonly ok: false; readonly error: string };

export function parseEvidenceDoc(text: string): ParseEvidenceResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    return { ok: false, error: `invalid evidence JSON: ${err instanceof Error ? err.message : String(err)}` };
  }
  const parsed = evidenceDocSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first && first.path.length > 0 ? ` at \`${first.path.join(".")}\`` : "";
    return { ok: false, error: `invalid evidence file${where}: ${first ? first.message : "validation failed"}` };
  }
  return { ok: true, doc: parsed.data };
}
