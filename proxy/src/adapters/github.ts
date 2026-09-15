/**
 * GitHub REST adapter: map (method, path) onto a normalized action.
 *
 * This is a v0 action taxonomy, ordered most-specific-first. It is deliberately
 * conservative: anything it cannot classify precisely falls back to a coarse
 * `repo:read` / `repo:write` / `api:read` / `api:write`, so that a policy which
 * only grants specific actions still fails closed on the long tail of endpoints.
 *
 * The taxonomy seeds the shared policy graph; extend the table, don't special-
 * case call sites.
 */
import type { AdapterOutcome, AdapterRequest, UpstreamAdapter } from "./types.ts";

interface Rule {
  readonly methods: readonly string[];
  readonly re: RegExp;
  readonly action: string;
}

const ANY = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;
const WRITE = ["POST", "PUT", "PATCH", "DELETE"] as const;

// Ordered: first match wins. Keep specific/destructive rules above general ones.
const RULES: readonly Rule[] = [
  // Repository lifecycle
  { methods: ["DELETE"], re: /^\/repos\/[^/]+\/[^/]+$/, action: "repo:delete" },

  // GitHub Actions (CI) — treated as a single high-risk surface
  { methods: ["GET"], re: /^\/repos\/[^/]+\/[^/]+\/actions(\/.*)?$/, action: "actions:read" },
  { methods: [...WRITE], re: /^\/repos\/[^/]+\/[^/]+\/actions(\/.*)?$/, action: "actions:write" },

  // Pull requests
  { methods: ["PUT"], re: /^\/repos\/[^/]+\/[^/]+\/pulls\/\d+\/merge$/, action: "pr:merge" },
  { methods: ["POST"], re: /^\/repos\/[^/]+\/[^/]+\/pulls$/, action: "pr:create" },
  { methods: ["PATCH"], re: /^\/repos\/[^/]+\/[^/]+\/pulls\/\d+$/, action: "pr:update" },
  // Review + issue comments (PRs are issues in the REST API) -> pr:comment
  {
    methods: ["POST"],
    re: /^\/repos\/[^/]+\/[^/]+\/(issues|pulls)\/\d+\/comments$/,
    action: "pr:comment",
  },
  { methods: ["GET"], re: /^\/repos\/[^/]+\/[^/]+\/pulls(\/.*)?$/, action: "pr:read" },

  // Issues
  { methods: ["POST"], re: /^\/repos\/[^/]+\/[^/]+\/issues$/, action: "issue:create" },
  { methods: ["PATCH"], re: /^\/repos\/[^/]+\/[^/]+\/issues\/\d+$/, action: "issue:update" },
  { methods: ["GET"], re: /^\/repos\/[^/]+\/[^/]+\/issues(\/.*)?$/, action: "issue:read" },

  // Contents / releases writes are destructive-ish
  { methods: ["PUT", "POST", "PATCH", "DELETE"], re: /^\/repos\/[^/]+\/[^/]+\/contents\//, action: "repo:write" },

  // Generic repo-scoped fallbacks
  { methods: ["GET", "HEAD"], re: /^\/repos\/[^/]+\/[^/]+(\/.*)?$/, action: "repo:read" },
  { methods: [...WRITE], re: /^\/repos\/[^/]+\/[^/]+(\/.*)?$/, action: "repo:write" },

  // User / org / search read surfaces
  { methods: ["GET", "HEAD"], re: /^\/user(\/.*)?$/, action: "user:read" },
  { methods: ["GET", "HEAD"], re: /^\/orgs\//, action: "org:read" },
  { methods: ["GET", "HEAD"], re: /^\/search\//, action: "search:read" },
];

/**
 * Every distinct canonical action this rule table can produce, including the
 * two coarse fallbacks. Derived, not hand-maintained, so it can never drift
 * from the actual classifier.
 */
export const GITHUB_ACTIONS: readonly string[] = Array.from(
  new Set([...RULES.map((r) => r.action), "api:read", "api:write"]),
);

/**
 * The path the rules are matched against.
 *
 * Repeated and trailing slashes are removed first, because the precise rules
 * are `$`-anchored and the coarse fallbacks are not: `DELETE /repos/o/r/` misses
 * `repo:delete` and lands on `repo:write`, so a policy that explicitly denies
 * `repo:delete` would let it through wearing a cheaper name. Whether GitHub
 * itself honours that spelling is not the point — Grenz has to be right about
 * the decision it makes, and "the upstream probably 404s it" is not a control
 * we own.
 *
 * Normalizing only ever makes an `$`-anchored rule match where a coarse
 * fallback did, so every path here classifies as the action it actually is.
 * The request forwards byte-for-byte as sent; this copy is for matching only.
 */
function normalizeForMatch(path: string): string {
  const collapsed = path.replace(/\/{2,}/g, "/").replace(/\/+$/, "");
  return collapsed === "" ? "/" : collapsed;
}

function classify(method: string, path: string): string {
  for (const rule of RULES) {
    if (rule.methods.includes(method) && rule.re.test(path)) return rule.action;
  }
  // Total fallback keyed only on method safety. Read vs. write, nothing else.
  return method === "GET" || method === "HEAD" ? "api:read" : "api:write";
}

export const githubAdapter: UpstreamAdapter = {
  type: "github",
  map(req: AdapterRequest): AdapterOutcome {
    if (!ANY.includes(req.method as (typeof ANY)[number])) {
      return { unsupported: `unsupported HTTP method: ${req.method}` };
    }
    const action = classify(req.method, normalizeForMatch(req.path));
    return { actions: [action], targets: [req.path], target: req.path, label: req.method };
  },
};
