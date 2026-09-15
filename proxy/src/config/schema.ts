/**
 * Zod schema for `grenz.yaml` — the non-secret runtime config.
 *
 * This file holds routing (which upstreams exist, where they live, which vault
 * key to inject and how) and agent identities (id + token hash). It contains no
 * credential values: those live only in the age vault.
 */
import { z } from "zod";
import { PROFILE_NAME_RE } from "../policy/profile-entry.ts";

export const injectSchema = z
  .object({
    /** Header the real credential is injected into on the upstream request. */
    header: z.string().min(1).default("Authorization"),
    /** Scheme prefix, e.g. `Bearer`. Empty string injects the raw value. */
    scheme: z.string().default("Bearer"),
  })
  .strict();

export const realUpstreamSchema = z
  .object({
    type: z.enum(["github", "mcp", "linear", "slack"]),
    base_url: z.string().url(),
    /** The vault key whose credential is injected for this upstream. */
    credential: z.string().min(1),
    inject: injectSchema.default({ header: "Authorization", scheme: "Bearer" }),
    decoy: z.literal(false).default(false),
  })
  .strict();

/** A decoy (honeytoken) upstream: no policy grants it and lint flags any grant
 *  that names it. It carries NO credential/base_url/inject — an armed decoy is
 *  unrepresentable, so nothing can forward a request to it. Touching it is
 *  high-confidence compromise; the toucher is revoked at dispatch. */
export const decoyUpstreamSchema = z
  .object({
    decoy: z.literal(true),
    type: z.enum(["github", "mcp", "linear", "slack"]),
  })
  .strict();

export const upstreamSchema = z.union([decoyUpstreamSchema, realUpstreamSchema]);

/** Max representable Date ms — the same bound used in decay-evidence. Keeps an
 *  `expiresAtMs` safe for doctor's `new Date(ms).toISOString()`. */
const MAX_TIME_MS = 8_640_000_000_000_000;

/** Cap on an agent's target globs — same bound the delegation store uses, so a
 *  standing agent and a sub-token it mints answer to the same ceiling. */
const MAX_AGENT_TARGETS = 100;
/** Cap on an agent's action globs — the other scope axis, same ceiling. */
const MAX_AGENT_ACTIONS = 100;

/** A profile name: lowercase, digit-led-or-alnum, `_`/`-` allowed, ≤64 chars.
 *  Same shape used for the map key and the agent's `policy` reference. */
export { PROFILE_NAME_RE };

/** Source of a named policy profile. `file` is OPTIONAL: a name-only
 *  declaration (`{}`, or a bare `ci:` — YAML `null`, preprocessed to `{}`)
 *  declares the profile exists without a local file; its content arrives via
 *  the Slice 3 signed bundle instead. When `file` IS given it is a LOCAL FILE
 *  PATH — resolved against the Grenz home, like other local paths. Not
 *  `policySourceSchema` (whose `url` is `z.string().url()`), which would
 *  reject bare paths AND admit unsigned `https://`. No http(s) for profiles
 *  until Slice 3's signed bundle. A value containing a URL scheme (`://`) is
 *  rejected so a misconfig fails loud. */
export const policyProfileSourceSchema = z.preprocess(
  (v) => v ?? {}, // a bare `ci:` parses to null → name-only {}
  z
    .object({
      file: z
        .string()
        .min(1)
        .refine((s) => !s.includes("://"), "policy_profiles: `file` must be a local path, not a URL")
        .optional(),
    })
    .strict(),
);

export const agentSchema = z
  .object({
    id: z.string().min(1),
    /** Hex SHA-256 of the agent's GRENZ_TOKEN. */
    token_hash: z.string().regex(/^[0-9a-f]{64}$/, "token_hash must be a hex SHA-256 digest"),
    /** A decoy (honeytoken) agent: no legitimate workload holds this token, so
     *  any request presenting it is high-confidence compromise. Tripped and
     *  revoked at dispatch; never a real identity. */
    decoy: z.boolean().default(false),
    /** Optional RFC 3339 instant (zone REQUIRED) after which this agent's token
     *  is rejected at resolve — the same 401 an unknown token gets. Absent =
     *  never expires (today's behavior). Re-mint with `grenz rotate`. */
    expires_at: z.string().datetime({ offset: true }).optional(),
    /** Optional target globs this agent's token is confined to — the ROOT scope
     *  of every delegation it mints. A request whose target matches none is
     *  denied `agent_target_scope`, even when the shared policy would allow the
     *  action. Absent = unrestricted (today's behavior); scope tightens per
     *  agent without touching the shared policy. Matched by the same glob engine
     *  as rule/delegation targets. */
    targets: z.array(z.string().min(1)).min(1).max(MAX_AGENT_TARGETS).optional(),
    /** Optional action globs this agent's token is confined to — the other scope
     *  axis, same ROOT-of-the-chain semantics as `targets`. A requested action
     *  matching none is denied `agent_action_scope`, even when the shared policy
     *  allows it. Absent = the agent may use every action the shared policy
     *  grants (today's behavior); a list narrows THIS agent to a subset without
     *  touching the shared policy. */
    actions: z.array(z.string().min(1)).min(1).max(MAX_AGENT_ACTIONS).optional(),
    /** Optional named profile (a key of top-level `policy_profiles`) whose GRANTS
     *  govern this agent. Absent = the shared default policy (today's behavior).
     *  A profile overrides grants ONLY — every protective construct is inherited
     *  from the default and cannot be weakened. Existence of the referenced key
     *  is checked at the config level (agentSchema cannot see policy_profiles). */
    policy: z.string().regex(PROFILE_NAME_RE, "policy must be a valid profile name").optional(),
  })
  .strict()
  .superRefine((a, ctx) => {
    if (a.expires_at !== undefined) {
      // Fail CLOSED on a value datetime() admits but Date.parse cannot (NaN <=
      // now is false → "never expires", a silent fail-OPEN). The bound also keeps
      // expiresAtMs safe for doctor's toISOString() (Date-overflow rule).
      const ms = Date.parse(a.expires_at);
      if (!Number.isFinite(ms) || ms < 0 || ms > MAX_TIME_MS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["expires_at"],
          message: "expires_at is not a representable instant",
        });
      }
    }
    // A decoy that expires is a decoy that stops watching: past expiry,
    // resolvePrincipal returns null BEFORE the decoy gate can fire, so a
    // compromise probe would log as routine expiry — inverted severity. Forbid.
    if (a.decoy && a.expires_at !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expires_at"],
        message: `decoy agent "${a.id}" must not set expires_at — a decoy that expires stops watching; remove it instead`,
      });
    }
    // A decoy trips + revokes at dispatch, BEFORE the target-scope fold ever
    // runs, so `targets` on a decoy would be silently inert. Reject it rather
    // than let an operator believe a decoy is scoped.
    if (a.decoy && a.targets !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["targets"],
        message: `decoy agent "${a.id}" must not set targets — a decoy is tripped before scope is evaluated; remove it`,
      });
    }
    if (a.decoy && a.actions !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actions"],
        message: `decoy agent "${a.id}" must not set actions — a decoy is tripped before scope is evaluated; remove it`,
      });
    }
    // A decoy is tripped + revoked at dispatch, before any policy is selected, so
    // a profile on it would be silently inert. Reject rather than mislead.
    if (a.decoy && a.policy !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["policy"],
        message: `decoy agent "${a.id}" must not set policy — a decoy is tripped before policy selection; remove it`,
      });
    }
  })
  .transform((a) => ({ ...a, expiresAtMs: a.expires_at ? Date.parse(a.expires_at) : null }));

export const listenSchema = z
  .object({
    host: z.string().min(1).default("127.0.0.1"),
    port: z.number().int().min(1).max(65535).default(8787),
    /**
     * Opt-in: serve AGENT routes (`/u/*`, `/delegate`) on this unix socket
     * instead of TCP. The admin plane (console, metrics, healthz) stays on
     * host/port, so `host`/`port` legitimately coexist with this. Relative
     * paths resolve against the Grenz home.
     *
     * This narrows WHO CAN REACH the agent listener to your own OS user — it
     * does not authenticate which process is the agent. Same-user processes are
     * inside the boundary.
     */
    socket: z
      .string()
      .min(1)
      .refine((s) => !s.includes("\0"), "listen.socket must not contain a NUL byte")
      .optional(),
  })
  .strict();

export const approvalsSchema = z
  .object({
    /** How long a `require_approval` request blocks before expiring → DENY. */
    ttl_seconds: z.number().int().positive().max(3600).default(300),
    /** Hard cap on concurrent pending approvals (held sockets/timers). */
    max_pending: z.number().int().positive().max(10000).default(100),
    /** Remember a human's approve/deny for the exact (agent, tool, action,
     *  target) this many seconds, so an identical retry doesn't re-prompt.
     *  0 (default) = off. */
    remember_seconds: z.number().int().min(0).max(3600).default(0),
  })
  .strict();

/**
 * The vault key the relay authenticates with. Not configurable, and defined
 * here rather than in the CLI so `grenz run` and `grenz doctor` cannot drift
 * about which key they are talking about.
 */
export const RELAY_TOKEN_KEY = "relay_token";

export const relaySchema = z
  .object({
    /** HTTPS base URL of the Grenz relay (e.g. https://relay.grenz.dev). The
     *  proxy POSTs approval metadata here and long-polls for the verdict. */
    url: z.string().url(),
    /** Long-poll window per outbound GET. Short windows keep each fetch well
     *  under Bun's ~255s connection cap and reconnect to cover the full TTL. */
    poll_window_seconds: z.number().int().positive().max(120).default(25),
  })
  .strict();

export const telemetrySchema = z
  .object({
    /** Opt-in: send anonymized aggregate stats (tool/action counts) to the plane. */
    enabled: z.boolean().default(false),
    endpoint: z.string().url(),
    /** Vault key holding the org token used to authenticate telemetry. */
    org_token_key: z.string().min(1).default("cloud_org_token"),
    interval_seconds: z.number().int().min(60).max(86400).default(3600),
  })
  .strict();

/** Hosts where plain http is the normal case: a dev plane on the same machine. */
export const LOCAL_PLANE_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * True when a URL is safe to send the org token to.
 *
 * Plain http is refused off localhost. The proxy sends its org token to this
 * URL and then RUNS whatever comes back, so over http anyone on the path both
 * learns the token and chooses the policy — and the policy they choose can just
 * say `allow: ["*"]`. Pinning a `public_key` closes the second half, but it is
 * optional here and does nothing for the first.
 *
 * `grenz connect` already refuses to WRITE such a config; this is the half that
 * refuses to RUN one, so a hand-edited grenz.yaml gets the same answer.
 */
export function isSafePlaneUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && LOCAL_PLANE_HOSTS.has(url.hostname);
}

const PLANE_URL_MESSAGE =
  "must be https (plain http is allowed only on localhost) — the proxy sends its org token to this URL and runs the policy that comes back, so over http anyone on the path learns the token and chooses the policy";

export const policySourceSchema = z
  .object({
    /** URL the proxy pulls its compiled-from policy YAML from at startup. */
    url: z.string().url().refine(isSafePlaneUrl, { message: PLANE_URL_MESSAGE }),
    org_token_key: z.string().min(1).default("cloud_org_token"),
    /**
     * Pinned Ed25519 verify keys (base64 raw). >=1 REQUIRES the source to serve a
     * signed bundle. Delivered out-of-band from the plane — the plane never holds
     * the signing key. A list allows rotation (add new, re-sign, drop old).
     */
    public_key: z.array(z.string().min(1)).default([]),
    /** Background re-pull interval. 0 (default) = pull at startup only. */
    refresh_seconds: z.union([z.literal(0), z.number().int().min(30).max(86400)]).default(0),
    /** Optional staleness bound (seconds since the last verified pull). */
    max_age_seconds: z.number().int().min(30).max(604800).optional(),
    /** What to do when the running policy is older than max_age_seconds. */
    on_stale: z.enum(["warn", "fail_closed"]).default("warn"),
    /** URL the proxy pulls the signed revocation set from (own, shorter clock).
     *  REQUIRES at least one pinned public_key — an unsigned revocation channel
     *  is strictly worse than none (an attacker who controls it serves an empty
     *  set = un-revoke everyone). */
    revocation_url: z.string().url().refine(isSafePlaneUrl, { message: PLANE_URL_MESSAGE }).optional(),
    /** Background re-pull interval for the revocation set. 0 (default) = pull at
     *  startup only. Independent of the policy refresh clock. */
    revocation_refresh_seconds: z.union([z.literal(0), z.number().int().min(30).max(86400)]).default(0),
    /** Optional staleness bound (seconds since the last verified revocation pull). */
    revocation_max_age_seconds: z.number().int().min(30).max(604800).optional(),
    /** What to do when the running revocation set is stale. warn (default) keeps
     *  enforcing the cached set; fail_closed denies ALL requests until a fresh
     *  signed set lands (opt-in liveness coupling). */
    on_revocation_stale: z.enum(["warn", "fail_closed"]).default("warn"),
  })
  .strict()
  // Staleness is only ever re-evaluated by the refresh loop, and fail_closed
  // needs a bound to act on. Rejecting the incoherent combinations at load beats
  // accepting a config that silently promises enforcement it cannot deliver.
  .superRefine((s, ctx) => {
    if (s.max_age_seconds !== undefined && s.refresh_seconds === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["max_age_seconds"],
        message:
          "policy_source.max_age_seconds requires refresh_seconds > 0 — with startup-only pulls the staleness bound is never re-evaluated",
      });
    }
    if (s.on_stale === "fail_closed" && s.max_age_seconds === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["on_stale"],
        message: "policy_source.on_stale: fail_closed requires max_age_seconds — there is no bound to act on",
      });
    }
    if (s.revocation_url !== undefined && s.public_key.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["revocation_url"],
        message:
          "policy_source.revocation_url requires at least one public_key — an unsigned revocation channel lets whoever serves it un-revoke the fleet",
      });
    }
    if (s.revocation_max_age_seconds !== undefined && s.revocation_refresh_seconds === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["revocation_max_age_seconds"],
        message:
          "policy_source.revocation_max_age_seconds requires revocation_refresh_seconds > 0 — with startup-only pulls the bound is never re-evaluated",
      });
    }
    if (s.on_revocation_stale === "fail_closed" && s.revocation_max_age_seconds === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["on_revocation_stale"],
        message:
          "policy_source.on_revocation_stale: fail_closed requires revocation_max_age_seconds — there is no bound to act on",
      });
    }
    // Staleness is only re-evaluated on the refresh tick, so a bound shorter than
    // the refresh interval cannot be enforced tightly (the proxy could be stale
    // for up to a full interval before it notices). Require the bound to be at
    // least the interval so fail_closed actually closes near its promised time.
    if (
      s.revocation_max_age_seconds !== undefined &&
      s.revocation_refresh_seconds > 0 &&
      s.revocation_max_age_seconds < s.revocation_refresh_seconds
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["revocation_max_age_seconds"],
        message:
          "policy_source.revocation_max_age_seconds must be >= revocation_refresh_seconds — staleness is only checked once per refresh, so a shorter bound cannot be enforced",
      });
    }
  });

const ageFileStoreSchema = z.object({ type: z.literal("age-file") }).strict();
const hashicorpVaultStoreSchema = z
  .object({
    type: z.literal("hashicorp-vault"),
    address: z.string().url(),
    mount: z.string().min(1).default("secret"),
    path_prefix: z.string().default("grenz/"),
    field: z.string().min(1).default("value"),
    token_key: z.string().min(1).default("hashivault_token"),
    cache_ttl_seconds: z.number().int().min(0).max(3600).default(60),
  })
  .strict();
/** Where UPSTREAM credentials are read from. age-file (the local encrypted vault)
 *  is the zero-config default; hashicorp-vault reads them from HashiCorp Vault. */
export const credentialStoreSchema = z
  .discriminatedUnion("type", [ageFileStoreSchema, hashicorpVaultStoreSchema])
  .default({ type: "age-file" });

const roleSchema = z.enum(["viewer", "approver", "admin"]);

/** OIDC/IdP federation (`sso:`) is a Grenz Enterprise feature and is not part of
 *  the OSS build. Rather than silently ignore an `sso:` block — which would let a
 *  proxy boot believing federation is active when it is not — the OSS config
 *  fails closed with a structured pointer to the enterprise docs. */
const ssoEnterpriseReject = z.unknown().superRefine((val, ctx) => {
  if (val !== undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message:
        "`sso:` (OIDC/IdP federation) is a Grenz Enterprise feature, not part of the OSS build. Remove the block, or see docs/enterprise.md.",
    });
  }
});

export const configSchema = z
  .object({
    listen: listenSchema.default({ host: "127.0.0.1", port: 8787 }),
    approvals: approvalsSchema.default({ ttl_seconds: 300 }),
    upstreams: z.record(z.string().min(1), upstreamSchema).default({}),
    agents: z.array(agentSchema).min(1, "at least one agent is required"),
    /** Named grant profiles (local files). A profile overrides GRANTS only; every
     *  protection is inherited from the default. Absent ⇒ today's behavior. */
    policy_profiles: z.record(z.string().regex(PROFILE_NAME_RE), policyProfileSourceSchema).default({}),
    /**
     * Bash command guard: serve `POST /exec` so `grenz hook` can gate a coding
     * agent's shell commands against the `bash` tool grant. Off by default —
     * enabling it loads the tree-sitter parser at startup and makes an agent
     * token usable for exec decisions as well as upstream requests.
     */
    exec_guard: z.boolean().default(false),
    /** Gate 4: opt-in anonymized telemetry to the team plane. */
    telemetry: telemetrySchema.optional(),
    /** Gate 4: pull policy from the team plane (falls back to local policy.yaml). */
    policy_source: policySourceSchema.optional(),
    /** Where upstream credentials are resolved from (default: local age file). */
    credential_store: credentialStoreSchema,
    /** OIDC/IdP federation is a Grenz Enterprise feature — an `sso:` block fails
     *  closed in the OSS build (see ssoEnterpriseReject). */
    sso: ssoEnterpriseReject.optional(),
    /** Grenz Relay: outbound-only approval return path for headless runners.
     *  When set (with a `relay_token` in the vault), approvals route to the
     *  relay instead of the local Slack/CLI path. */
    relay: relaySchema.optional(),
  })
  .strict()
  // Agent identity is possession of a token: `resolvePrincipal` (auth.ts) hashes
  // the presented token and matches against the configured hashes. Two agents
  // that share a `token_hash` are two identities behind one token — the match
  // loop would silently pick whichever came last, so per-agent budgets,
  // revocation, and first-use gating attach to an arbitrary one. Two agents that
  // share an `id` are the same ambiguity for the human-meaningful unit that
  // `grenz revoke`/`grenz risk` report. Both are pathological; refuse the
  // ambiguous config at load rather than resolve it unpredictably.
  .superRefine((cfg, ctx) => {
    const seenIds = new Set<string>();
    const seenHashes = new Set<string>();
    cfg.agents.forEach((agent, i) => {
      if (seenIds.has(agent.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["agents", i, "id"],
          message: `duplicate agent id "${agent.id}" — each agent id must be unique`,
        });
      }
      seenIds.add(agent.id);
      if (seenHashes.has(agent.token_hash)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["agents", i, "token_hash"],
          message:
            "duplicate token_hash — two agents share one token, so their identity cannot be resolved unambiguously",
        });
      }
      seenHashes.add(agent.token_hash);
    });
    // Every agent `policy` must name a defined profile — fail closed at load, so
    // the request-path deny is only a safety net for states the loader can't see.
    const profileNames = new Set(Object.keys(cfg.policy_profiles));
    cfg.agents.forEach((agent, i) => {
      if (agent.policy !== undefined && !profileNames.has(agent.policy)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["agents", i, "policy"],
          message: `agent "${agent.id}" references undefined profile "${agent.policy}" — add it to policy_profiles`,
        });
      }
    });
  });

export type GrenzConfig = z.infer<typeof configSchema>;
export type UpstreamConfig = z.infer<typeof upstreamSchema>;
export type RealUpstreamConfig = z.infer<typeof realUpstreamSchema>;
export type AgentConfig = z.infer<typeof agentSchema>;
export type PolicyProfileSource = z.infer<typeof policyProfileSourceSchema>;
