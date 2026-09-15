/**
 * Pure logic for `grenz add`: merge a template into parsed config + policy
 * objects. No IO — the caller parses the YAML, calls this, re-validates, and
 * writes. Returns a structured error rather than throwing (fail closed).
 */
import type { PolicyTemplate } from "./templates.ts";

interface UpstreamEntry {
  type: string;
  base_url: string;
  credential: string;
}

interface GrantEntry {
  tool: string;
  allow?: string[];
  deny?: string[];
  require_approval?: string[];
}

interface ConfigShape {
  upstreams?: Record<string, UpstreamEntry>;
  [key: string]: unknown;
}

interface PolicyShape {
  grants?: GrantEntry[];
  [key: string]: unknown;
}

export interface ApplyInput {
  readonly configObj: ConfigShape;
  readonly policyObj: PolicyShape;
  readonly upstreamName: string;
  readonly credentialKey: string;
  readonly template: PolicyTemplate;
}

export type ApplyResult =
  | { readonly ok: true; readonly config: ConfigShape; readonly policy: PolicyShape }
  | { readonly ok: false; readonly error: string };

export function applyTemplate(input: ApplyInput): ApplyResult {
  const { upstreamName, credentialKey, template } = input;
  const config: ConfigShape = structuredClone(input.configObj);
  const policy: PolicyShape = structuredClone(input.policyObj);

  const upstreams: Record<string, UpstreamEntry> = { ...(config.upstreams ?? {}) };
  const existing = upstreams[upstreamName];
  if (existing && existing.type !== template.type) {
    return {
      ok: false,
      error: `upstream "${upstreamName}" already exists with type "${existing.type}" (template is "${template.type}")`,
    };
  }
  if (!existing) {
    upstreams[upstreamName] = {
      type: template.type,
      base_url: template.baseUrl,
      credential: credentialKey,
    };
  }
  config.upstreams = upstreams;

  const grants: GrantEntry[] = Array.isArray(policy.grants) ? [...policy.grants] : [];
  if (grants.some((g) => g && g.tool === upstreamName)) {
    return {
      ok: false,
      error: `policy already has a grant for "${upstreamName}" — edit it by hand or remove it first`,
    };
  }
  const grant: GrantEntry = { tool: upstreamName };
  if (template.grant.allow) grant.allow = [...template.grant.allow];
  if (template.grant.require_approval) grant.require_approval = [...template.grant.require_approval];
  if (template.grant.deny) grant.deny = [...template.grant.deny];
  grants.push(grant);
  policy.grants = grants;

  return { ok: true, config, policy };
}
