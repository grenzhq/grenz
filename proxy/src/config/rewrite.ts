/**
 * Targeted edits to grenz.yaml text, preserving the file's comments and
 * formatting (the init template is heavily commented). Every function here is
 * pure and synchronous, substitutes values a caller already computed, and fails
 * closed on a malformed file or a target that isn't there.
 */
import { parseDocument, isSeq, isMap, isPair, isScalar, Scalar, type Document } from "yaml";

/** Attach a comment ABOVE a top-level key. `commentBefore` on the value node
 *  lands the text inside the block (after `key:`), which reads as machine
 *  output; on the key node it sits above the key, where a person would put it.
 *  `doc.set` stores a plain string key, which carries no comment — so the key
 *  is replaced with a Scalar node that can. */
function commentTopLevelKey(doc: Document, key: string, text: string): void {
  const items = (doc.contents as { items?: unknown[] } | null)?.items ?? [];
  for (const item of items) {
    if (!isPair(item)) continue;
    const k = item.key;
    if ((isScalar(k) ? k.value : k) !== key) continue;
    const node = isScalar(k) ? k : new Scalar(key);
    node.commentBefore = text;
    (item as { key: unknown }).key = node;
    return;
  }
}


export type RewriteResult =
  | { readonly ok: true; readonly yaml: string }
  | { readonly ok: false; readonly error: string };

export function setAgentTokenHash(rawYaml: string, agentId: string, newHash: string): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) {
    return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  }

  const agents = doc.get("agents");
  if (!isSeq(agents)) {
    return { ok: false, error: "grenz.yaml has no agents list" };
  }

  let idx = -1;
  agents.items.forEach((item, i) => {
    if (isMap(item) && item.get("id") === agentId) idx = i;
  });
  if (idx < 0) {
    return { ok: false, error: `unknown agent "${agentId}"` };
  }

  doc.setIn(["agents", idx, "token_hash"], newHash);
  return { ok: true, yaml: doc.toString() };
}

/** Append a decoy agent entry. Fails closed on a malformed file, a missing
 *  agents list, or an id that already exists. Comment-preserving. */
export function addDecoyAgent(rawYaml: string, id: string, tokenHash: string): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  const agents = doc.get("agents");
  if (!isSeq(agents)) return { ok: false, error: "grenz.yaml has no agents list" };
  const exists = agents.items.some((it) => isMap(it) && it.get("id") === id);
  if (exists) return { ok: false, error: `agent "${id}" already exists` };
  agents.add(doc.createNode({ id, token_hash: tokenHash, decoy: true }));
  return { ok: true, yaml: doc.toString() };
}

/** Append a first-class (non-decoy) agent entry. Fails closed on a malformed
 *  file, a missing agents list, or an id that already exists. Comment-preserving
 *  — the console mint path uses this so a hand-commented grenz.yaml survives.
 *  A non-empty `scope.actions`/`scope.targets` writes the matching list confining
 *  the agent's reach (see agentSchema); empty/absent leaves that axis
 *  unrestricted. */
export function addAgent(
  rawYaml: string,
  id: string,
  tokenHash: string,
  scope?: {
    readonly actions?: readonly string[];
    readonly targets?: readonly string[];
    /** Named policy profile governing this agent (a key of policy_profiles).
     *  Absent = the shared default. Validated against live profiles by the caller. */
    readonly policy?: string;
  },
): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  const agents = doc.get("agents");
  if (!isSeq(agents)) return { ok: false, error: "grenz.yaml has no agents list" };
  const exists = agents.items.some((it) => isMap(it) && it.get("id") === id);
  if (exists) return { ok: false, error: `agent "${id}" already exists` };
  const entry: Record<string, unknown> = { id, token_hash: tokenHash };
  if (scope?.policy) entry.policy = scope.policy;
  if (scope?.actions && scope.actions.length > 0) entry.actions = [...scope.actions];
  if (scope?.targets && scope.targets.length > 0) entry.targets = [...scope.targets];
  agents.add(doc.createNode(entry));
  return { ok: true, yaml: doc.toString() };
}

/** Add a decoy upstream `<name>: { decoy: true, type: mcp }`. Creates the
 *  upstreams map if absent. Fails closed on a name collision. Comment-preserving. */
export function addDecoyUpstream(rawYaml: string, name: string): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  let upstreams = doc.get("upstreams");
  if (upstreams === undefined || upstreams === null) {
    doc.set("upstreams", doc.createNode({}));
    upstreams = doc.get("upstreams");
  }
  if (!isMap(upstreams)) return { ok: false, error: "grenz.yaml upstreams is not a mapping" };
  if (upstreams.has(name)) return { ok: false, error: `upstream "${name}" already exists` };
  upstreams.set(name, doc.createNode({ decoy: true, type: "mcp" }));
  return { ok: true, yaml: doc.toString() };
}

/** Remove a decoy agent by id. Refuses to remove a non-decoy agent (never a
 *  footgun for real identities) or an unknown id. */
export function removeDecoyAgent(rawYaml: string, id: string): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  const agents = doc.get("agents");
  if (!isSeq(agents)) return { ok: false, error: "grenz.yaml has no agents list" };
  const idx = agents.items.findIndex((it) => isMap(it) && it.get("id") === id);
  if (idx < 0) return { ok: false, error: `unknown agent "${id}"` };
  const item = agents.items[idx];
  if (!(isMap(item) && item.get("decoy") === true)) {
    return { ok: false, error: `agent "${id}" is not a decoy — refusing to remove` };
  }
  agents.delete(idx);
  return { ok: true, yaml: doc.toString() };
}

/** Remove a decoy upstream by name. Refuses a non-decoy upstream or unknown name. */
export function removeDecoyUpstream(rawYaml: string, name: string): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  const upstreams = doc.get("upstreams");
  if (!isMap(upstreams)) return { ok: false, error: "grenz.yaml has no upstreams map" };
  const entry = upstreams.get(name);
  if (entry === undefined) return { ok: false, error: `unknown upstream "${name}"` };
  if (!(isMap(entry) && entry.get("decoy") === true)) {
    return { ok: false, error: `upstream "${name}" is not a decoy — refusing to remove` };
  }
  upstreams.delete(name);
  return { ok: true, yaml: doc.toString() };
}

/**
 * Point this proxy at a control plane: write the `policy_source` block.
 *
 * Exists because the alternative is telling someone to hand-paste an
 * indentation-sensitive block into a file they have never opened — the single
 * biggest step in setup, and the one most likely to be got wrong silently.
 *
 * Refuses to overwrite an existing block without `force`: a `policy_source`
 * already in the file may carry a pinned `public_key`, and quietly replacing
 * that with an unpinned one is a downgrade from verified to trusted-transport.
 * Comment-preserving, like everything else here.
 */
export function setPolicySource(
  rawYaml: string,
  source: {
    readonly url: string;
    readonly orgTokenKey: string;
    readonly refreshSeconds: number;
    readonly maxAgeSeconds: number;
    /** Pinned Ed25519 verify keys. Non-empty REQUIRES a signed bundle — the
     *  stronger mode, so it has to be as easy to write as the unsigned one. */
    readonly publicKeys?: readonly string[];
  },
  force = false,
): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  if (doc.has("policy_source") && !force) {
    return { ok: false, error: "policy_source is already set — re-run with --force to replace it" };
  }
  const entry: Record<string, unknown> = { url: source.url, org_token_key: source.orgTokenKey };
  if (source.publicKeys && source.publicKeys.length > 0) entry.public_key = [...source.publicKeys];
  entry.refresh_seconds = source.refreshSeconds;
  entry.max_age_seconds = source.maxAgeSeconds;
  entry.on_stale = "fail_closed";
  const node = doc.createNode(entry);
  doc.set("policy_source", node);
  commentTopLevelKey(
    doc,
    "policy_source",
    " Where this proxy pulls its policy. Decisions still happen here, offline,\n" +
      " on the last policy that arrived; on_stale: fail_closed means a policy older\n" +
      " than max_age_seconds stops being served rather than being trusted.",
  );
  return { ok: true, yaml: doc.toString() };
}

/**
 * Write the `telemetry` block. Separate from `setPolicySource` and never
 * implied by it: telemetry is egress, it is opt-in in the schema, and a command
 * that switched it on as a side effect of connecting would be turning on data
 * flow the operator did not ask for.
 */
export function setTelemetry(
  rawYaml: string,
  telemetry: { readonly endpoint: string; readonly orgTokenKey: string; readonly intervalSeconds: number },
  force = false,
): RewriteResult {
  const doc = parseDocument(rawYaml);
  if (doc.errors.length > 0) return { ok: false, error: `invalid grenz.yaml: ${doc.errors[0]!.message}` };
  if (doc.has("telemetry") && !force) {
    return { ok: false, error: "telemetry is already set — re-run with --force to replace it" };
  }
  const node = doc.createNode({
    enabled: true,
    endpoint: telemetry.endpoint,
    org_token_key: telemetry.orgTokenKey,
    interval_seconds: telemetry.intervalSeconds,
  });
  doc.set("telemetry", node);
  commentTopLevelKey(
    doc,
    "telemetry",
    " Aggregate counts per tool and action — never a target, a request body, or\n" +
      " a credential. Delete this block to send nothing.",
  );
  return { ok: true, yaml: doc.toString() };
}
