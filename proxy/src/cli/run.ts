/**
 * `grenz run` — load config + policy, open the vault, start the proxy.
 *
 * Fails closed: a malformed policy or missing identity aborts startup rather
 * than serving with an unknown ruleset.
 */
import { loadAll, ConfigError } from "../config/load.ts";
import { expiryStatus } from "../config/expiry.ts";
import { AgeFileCredentialStore } from "../vault/age-file.ts";
import { HashicorpVaultCredentialStore } from "../vault/hashicorp-vault.ts";
import { VaultError, type CredentialStore } from "../vault/store.ts";
import { RequestLog } from "../log/request-log.ts";
import { startServer, startSocketServer, approvalHoldNote } from "../proxy/server.ts";
import { resolveSocketPath } from "../config/socket-path.ts";
import { loadBashParser } from "../exec/parser.ts";
import { lintExec } from "../policy/lint.ts";
import { prepareSocketDir, bindWithRecovery, finalizeSocket } from "../run/socket.ts";
import { ApprovalBroker } from "../approvals/broker.ts";
import { ApprovalMemory } from "../approvals/memory.ts";
import { SlackNotifier } from "../notify/slack.ts";
import { RelayChannel } from "../notify/relay.ts";
import { nullNotifier, type Notifier } from "../notify/notifier.ts";
import { ensureAdminToken } from "../admin/token.ts";
import { RevocationStore, RevocationError } from "../revoke/store.ts";
import { DelegationStore, DelegationError } from "../delegate/store.ts";
import { GrantStore, GrantError } from "../grant/store.ts";
import { BreakGlassStore, BreakGlassError } from "../breakglass/store.ts";
import { FlowFactStore } from "../flow/facts.ts";
import { PinStore } from "../pin/store.ts";
import { TokenStore, TokenStoreError } from "../admin/token-store.ts";
import { CanaryStore } from "../canary/store.ts";
import { compilePolicyYaml, type CompiledPolicy } from "../policy/compile.ts";
import { fetchRemotePolicy, fetchSignedPolicy } from "../policy/source.ts";
import { PolicyVersionStore } from "../distribution/version-store.ts";
import { refreshOnce, refreshUnsignedOnce, isStale, denyAllYaml } from "../distribution/refresh.ts";
import { policyDigest } from "../distribution/verify.ts";
import type { PolicyDistributionState } from "../distribution/types.ts";
import { FleetRevocationStore, FleetRevocationError } from "../revocation/store.ts";
import { fetchRevocationSet } from "../revocation/source.ts";
import { refreshRevocationsOnce, isRevocationStale } from "../revocation/refresh.ts";
import type { RevocationDistributionState } from "../revocation/types.ts";
import { CloudStatsReporter, nullReporter, StatsWindow, type StatsReporter } from "../telemetry/stats.ts";
import { scoreRisk } from "../risk/score.ts";
import { RELAY_TOKEN_KEY } from "../config/schema.ts";
import { flagBool, flagString, homeFlag, type ParsedArgs } from "./args.ts";
import { PolicyStore } from "../policy/store.ts";
import { adoptSignedStartup, startupProfileEntries } from "./run-profiles.ts";
import type { ProfileEntry } from "../policy/profile-entry.ts";
import { PolicyHistoryStore } from "../policy/history-store.ts";
import { AgentStore } from "../agents/store.ts";
import { Mutex } from "../util/mutex.ts";
import { watch as fsWatch, type FSWatcher } from "node:fs";

const SLACK_WEBHOOK_KEY = "slack_webhook";
/** How soon after start the first telemetry report goes out. */
const FIRST_REPORT_MS = 60_000;

export async function runRun(args: ParsedArgs): Promise<number> {
  const home = homeFlag(args);

  let loaded;
  try {
    loaded = await loadAll(home);
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  const { paths } = loaded;
  const config = loaded.config;
  let policy = loaded.policy; // may be replaced by a pulled remote policy below

  const portFlag = flagString(args, "port");
  if (portFlag !== undefined) {
    const port = Number(portFlag);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      process.stderr.write(`grenz: invalid --port "${portFlag}"\n`);
      return 1;
    }
    config.listen.port = port;
  }

  // --host overrides the bind address. Needed in containers, where binding the
  // default 127.0.0.1 makes a published port (-p) unreachable; use 0.0.0.0 there
  // and rely on the container/host network boundary plus the GRENZ_TOKEN.
  const hostFlag = flagString(args, "host");
  if (hostFlag !== undefined && hostFlag.length > 0) {
    config.listen.host = hostFlag;
  }

  const shadow = flagBool(args, "shadow");
  const watch = flagBool(args, "watch");

  // Shadow-policy canary: a candidate policy previewed against live traffic.
  // Fail closed — a broken candidate must not start a misleading run.
  const canaryPath = flagString(args, "canary");
  let canaryPolicy: CompiledPolicy | undefined;
  let canaryStore: CanaryStore | undefined;
  let canaryLine = "off";
  if (canaryPath !== undefined && canaryPath.length > 0) {
    let candidateYaml: string;
    try {
      candidateYaml = await Bun.file(canaryPath).text();
    } catch {
      process.stderr.write(`grenz: --canary: could not read ${canaryPath}\n`);
      return 1;
    }
    const compiled = compilePolicyYaml(candidateYaml);
    if (!compiled.ok) {
      process.stderr.write(`grenz: --canary: ${compiled.error}\n`);
      return 1;
    }
    canaryPolicy = compiled.policy;
    canaryStore = new CanaryStore();
    canaryLine = `${canaryPath} (loaded)`;
  }

  const localVault = new AgeFileCredentialStore({ identityPath: paths.identity, vaultPath: paths.vault });
  try {
    // Force the local vault to load now so a missing identity fails fast and loud.
    await localVault.keys();
  } catch (err) {
    if (err instanceof VaultError) {
      process.stderr.write(`grenz: vault error (${err.code}): ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // Select the store that resolves UPSTREAM credentials. Meta-credentials
  // (slack_webhook, cloud_org_token, and the Vault bootstrap token) ALWAYS come
  // from the local age store below — never the remote one (avoids a
  // self-referential token lookup and keeps meta-lookups from silently changing
  // meaning when a remote backend is configured).
  let vault: CredentialStore = localVault;
  let secretsLine = "age-file (local)";
  const cs = config.credential_store;
  if (cs.type === "hashicorp-vault") {
    const token = process.env.VAULT_TOKEN ?? (await localVault.get(cs.token_key));
    if (!token) {
      process.stderr.write(
        `grenz: hashicorp-vault backend needs a token — set VAULT_TOKEN or ` +
          `\`grenz vault set ${cs.token_key}\`\n`,
      );
      return 1;
    }
    vault = new HashicorpVaultCredentialStore({
      address: cs.address,
      mount: cs.mount,
      pathPrefix: cs.path_prefix,
      field: cs.field,
      token,
      cacheTtlMs: cs.cache_ttl_seconds * 1000,
    });
    try {
      // Connectivity + token check — a bad token/address dies loudly HERE, not as
      // a 502 storm on the first agent request.
      await vault.keys();
    } catch (err) {
      const msg = err instanceof VaultError ? err.message : "unreachable";
      process.stderr.write(`grenz: cannot reach HashiCorp Vault at ${cs.address} (${msg})\n`);
      return 1;
    }
    secretsLine = `hashicorp-vault @ ${cs.address}`;
  }

  // Gate 4: pull policy from the team plane if configured. Cloud distributes,
  // proxy compiles + decides locally (invariant 3); falls back to local on any
  // failure so a plane outage never takes the proxy down.
  //
  // With `policy_source.public_key` pinned, the bundle must carry a valid
  // Ed25519 signature from a key the plane never holds, and its version must
  // exceed the persisted floor (anti-rollback). A compromised plane can then
  // serve only what the org already signed. Verification is a LOAD-time
  // ceremony — nothing on the request path touches a signature.
  const pinnedKeys = config.policy_source?.public_key ?? [];
  const signedMode = config.policy_source !== undefined && pinnedKeys.length > 0;
  const policyDistribution: PolicyDistributionState = { version: 0, digest: "", lastVerifiedPullAt: 0 };
  let versionStore: PolicyVersionStore | null = null;
  let orgTokenForRefresh: string | null = null;

  // Profile source of truth for the store below. In signed mode the entries come
  // ONLY from the bundle — the validated set on a good pull, [] on a failed one —
  // never from local files (F2). These two are the raw inputs; the F2 selection
  // itself runs through startupProfileEntries() at the store-construction site so
  // the rule lives in ONE place. Non-signed mode keeps the local entries.
  const declaredNames = new Set(Object.keys(config.policy_profiles));
  let signedPullOk = false;
  let bundleEntries: readonly ProfileEntry[] = [];

  if (config.policy_source) {
    const orgToken = await localVault.get(config.policy_source.org_token_key);
    if (!orgToken && signedMode) {
      // A pinned key is an explicit statement that this proxy must run org-signed
      // policy. Silently falling back to the local file would be the downgrade
      // the pin exists to prevent, so refuse to start (matching the Vault check).
      process.stderr.write(
        `grenz: policy_source pins a public_key but vault key "${config.policy_source.org_token_key}" is missing —\n` +
          `        refusing to start rather than silently running unsigned local policy.\n` +
          `        Set it with: printf %s "$ORG_TOKEN" | grenz vault set ${config.policy_source.org_token_key}\n`,
      );
      return 1;
    }
    if (!orgToken) {
      process.stderr.write(
        `grenz: policy_source set but vault key "${config.policy_source.org_token_key}" is missing — using local policy.yaml\n`,
      );
    } else if (signedMode) {
      orgTokenForRefresh = orgToken;
      try {
        versionStore = new PolicyVersionStore(paths.policyVersion);
      } catch (err) {
        process.stderr.write(`grenz: ${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
      const signed = await fetchSignedPolicy(config.policy_source.url, orgToken, pinnedKeys, versionStore.floor());
      if (signed.ok) {
        // Validate the bundle's profiles BEFORE burning the anti-rollback floor
        // (F1): accept runs ONLY through adoptSignedStartup, after a clean merge.
        // A present-but-bad/undeclared profile refuses the whole bundle and the
        // floor is left un-advanced; an absent `profiles` clears rather than
        // freezes (F3, via entries ⇒ []).
        const adopt = adoptSignedStartup({
          signed,
          declaredNames,
          accept: (v, at) => versionStore!.accept(v, at),
          now: () => Date.now(),
        });
        if (!adopt.ok) {
          process.stderr.write(
            `grenz: signed bundle profiles unusable (${adopt.error}) — refusing to start\n`,
          );
          return 1; // floor NOT accepted — nothing adopted (F1)
        }
        policy = signed.policy;
        bundleEntries = adopt.entries;
        signedPullOk = true;
        policyDistribution.version = signed.version;
        policyDistribution.digest = signed.digest;
        policyDistribution.lastVerifiedPullAt = adopt.at;
        process.stdout.write(
          `grenz: pulled signed policy v${signed.version} (${signed.digest}) from ${config.policy_source.url}\n`,
        );
      } else {
        // Fall back to the local DEFAULT policy, but NEVER to local profiles: in
        // signed mode profiles are the bundle's alone, so an unavailable bundle
        // means no profiles (declared-profile agents then deny) (F2). signedPullOk
        // stays false ⇒ startupProfileEntries() yields [] at the store below.
        process.stderr.write(
          `grenz: signed policy pull failed (${signed.error}) — fell back to local policy.yaml\n` +
            (config.policy_source.on_stale === "fail_closed"
              ? "        on_stale: fail_closed — with no verified pull this proxy denies everything until one lands.\n"
              : ""),
        );
      }
    } else {
      orgTokenForRefresh = orgToken;
      const remote = await fetchRemotePolicy(config.policy_source.url, orgToken);
      if (remote.ok) {
        policy = remote.policy;
        // Start the liveness clock. Without this the staleness check below sees
        // a proxy that has never pulled and closes one that just pulled fine.
        policyDistribution.lastVerifiedPullAt = Date.now();
        policyDistribution.digest = await policyDigest(remote.policyYaml);
        process.stdout.write(`grenz: pulled policy from ${config.policy_source.url}\n`);
      } else {
        // lastVerifiedPullAt stays 0 — infinitely stale. With on_stale:
        // fail_closed that is what swaps the proxy to deny-all below, instead
        // of quietly serving local rules the operator did not ask it to serve.
        process.stderr.write(
          `grenz: policy pull failed (${remote.error}) — fell back to local policy.yaml\n` +
            (config.policy_source.on_stale === "fail_closed"
              ? "        on_stale: fail_closed — with no verified pull this proxy denies everything until one lands.\n"
              : ""),
        );
      }
      process.stderr.write(
        "grenz: policy_source has no public_key — the pull is unsigned, so whoever serves that URL controls this proxy's rules.\n" +
          "        Pin a key: grenz policy keygen, then set policy_source.public_key.\n",
      );
    }
  }

  // Fleet-propagated revocation: pull a signed current-state kill-set and union
  // it with local revocations at the gate. Same trust root as policy (pinnedKeys).
  // The cached set persists, so a plane outage never un-revokes the fleet.
  let fleetRevocations: FleetRevocationStore | null = null;
  const revocationDistribution: RevocationDistributionState = {
    version: 0,
    count: 0,
    expiresAt: null,
    lastVerifiedPullAt: 0,
    staleClosed: false,
  };
  const revSrc = config.policy_source;
  if (revSrc?.revocation_url && signedMode) {
    try {
      fleetRevocations = new FleetRevocationStore(paths.fleetRevocations);
    } catch (err) {
      if (err instanceof FleetRevocationError) {
        process.stderr.write(`grenz: ${err.message}\n`);
        return 1;
      }
      throw err;
    }
    // Seed runtime state from the persisted set so staleness (esp. expires_at) is
    // meaningful even before the first successful pull this run.
    revocationDistribution.version = fleetRevocations.version();
    revocationDistribution.count = fleetRevocations.count();
    revocationDistribution.expiresAt = fleetRevocations.expiresAt();

    // signedMode + a present revocation_url means the org token check above
    // already passed (a pinned key with a missing token returns 1), so
    // orgTokenForRefresh is non-null here.
    if (orgTokenForRefresh) {
      const first = await fetchRevocationSet(
        revSrc.revocation_url,
        orgTokenForRefresh,
        pinnedKeys,
        fleetRevocations.floor(),
      );
      if (first.ok) {
        const at = Date.now();
        let adopted = true;
        if (!first.unchanged) {
          try {
            fleetRevocations.replace(first.revokedAgents, first.version, first.expiresAt, at);
          } catch (err) {
            // A boot-time persist failure (e.g. disk full) must not abort startup:
            // keep enforcing the still-safe cached set rather than exiting.
            adopted = false;
            process.stderr.write(
              `grenz: could not persist pulled revocation set (${err instanceof Error ? err.message : String(err)}) — enforcing the cached set\n`,
            );
          }
        }
        if (adopted) {
          revocationDistribution.version = first.version;
          revocationDistribution.count = first.revokedAgents.length;
          revocationDistribution.expiresAt = first.expiresAt;
          revocationDistribution.lastVerifiedPullAt = at;
          process.stdout.write(
            `grenz: pulled signed revocation set v${first.version} (${first.revokedAgents.length} cut off fleet-wide)\n`,
          );
        }
      } else {
        process.stderr.write(`grenz: revocation pull failed (${first.error}) — enforcing the cached set\n`);
      }
    }
  }

  const log = new RequestLog(paths.db);

  // Hot-reload: the live policy is read through this store per request. Under
  // --watch it is swapped on a successful recompile; otherwise it never changes.
  // F2: in signed mode startupEntries is bundle-only (empty on pull failure), NEVER loaded.entries.
  const startupEntries = startupProfileEntries({
    signedMode,
    signedPullOk,
    bundleEntries,
    localEntries: loaded.entries,
  });
  const policyStore = new PolicyStore(policy, declaredNames, startupEntries);
  const profileCount = policyStore.profileNames.length;
  if (profileCount > 0) {
    const restartNote = signedMode ? "" : " — profile edits take effect on restart";
    process.stdout.write(`grenz: ${profileCount} policy profile(s) active${restartNote}\n`);
  }

  // Live agent set: initialized from config, appended to by a console mint so a
  // new agent authenticates without a restart. One write-lock serializes mints
  // (and guards the grenz.yaml rewrite against a concurrent mint).
  const agentStore = new AgentStore(config.agents);
  const configWriteLock = new Mutex();

  // Policy version history (operator convenience, truncatable — not audit).
  // Capture the local policy.yaml the proxy is adopting, unless policy is pulled
  // from the plane (then the local file isn't what's running).
  const policyHistory = new PolicyHistoryStore(paths.policyHistory);
  if (!config.policy_source) {
    try {
      policyHistory.record(await Bun.file(paths.policy).text(), Date.now());
    } catch {
      /* capture is best-effort; never block startup */
    }
  }

  // Gate 2 wiring: approval broker, optional Slack notifier, admin token.
  const broker = new ApprovalBroker(config.approvals.ttl_seconds * 1000, config.approvals.max_pending);
  // Approval memory: reuse a recent human decision for an identical request.
  // Constructed only when opted in — absent means every prompt asks a human.
  const approvalMemory =
    config.approvals.remember_seconds > 0
      ? new ApprovalMemory(config.approvals.remember_seconds * 1000)
      : undefined;
  const emit = (line: string): void => {
    process.stderr.write(`${line}\n`);
  };

  // Startup expiry banner: surface any agent whose token has already lapsed or
  // expires within the week, so an operator sees it now rather than at the first
  // masked 401. Purely a stderr notice — enforcement lives in resolvePrincipal.
  for (const agent of config.agents) {
    const expiresAtMs = agent.expiresAtMs;
    if (expiresAtMs === null) continue;
    const status = expiryStatus(expiresAtMs, Date.now());
    if (status === "expired" || status === "soon") {
      emit(`[agents] "${agent.id}" token ${status} (${new Date(expiresAtMs).toISOString()})`);
    }
  }

  // Relay wins when configured: a headless runner needs the outbound return
  // path, not a fire-and-forget local push. Falls back to Slack, then null.
  const relayToken = config.relay ? await localVault.get(RELAY_TOKEN_KEY) : null;
  const slackWebhook = await localVault.get(SLACK_WEBHOOK_KEY);
  let notifier: Notifier;
  if (config.relay && relayToken && relayToken.length > 0) {
    notifier = new RelayChannel(
      {
        url: config.relay.url,
        token: relayToken,
        pollWindowMs: config.relay.poll_window_seconds * 1000,
        emit,
      },
      broker,
    );
  } else if (slackWebhook && slackWebhook.length > 0) {
    notifier = new SlackNotifier(slackWebhook, emit);
  } else {
    notifier = nullNotifier;
  }
  const adminToken = await ensureAdminToken(paths.adminToken);

  // Named admin tokens (console RBAC). Fail-closed load, like the other stores.
  let tokenStore: TokenStore;
  try {
    tokenStore = new TokenStore(paths.adminTokens);
  } catch (err) {
    if (err instanceof TokenStoreError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // Kill-switch: load the persisted revocation list. A corrupt file fails
  // closed — refuse to serve with an unknown kill-list rather than silently
  // treating every agent as un-revoked.
  let revocations: RevocationStore;
  try {
    revocations = new RevocationStore(paths.revocations);
  } catch (err) {
    if (err instanceof RevocationError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }

  // Delegation: attenuated sub-tokens for spawned sub-agents. Same fail-closed
  // posture as the kill-list; expired grants are swept at startup.
  let delegations: DelegationStore;
  try {
    delegations = new DelegationStore(paths.delegations);
  } catch (err) {
    if (err instanceof DelegationError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  delegations.purgeExpired(Date.now());

  // JIT grants: temporary widenings of an agent's own token. Same fail-closed
  // posture as the kill-list/delegations; expired grants are swept at startup.
  let grants: GrantStore;
  try {
    grants = new GrantStore(paths.grants);
  } catch (err) {
    if (err instanceof GrantError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  grants.purgeExpired(Date.now());

  // Break-glass windows: loud, time-boxed admin unlocks. Same fail-closed posture
  // as the kill-list/grants; expired windows are swept at startup.
  let breakGlass: BreakGlassStore;
  try {
    breakGlass = new BreakGlassStore(paths.breakGlass);
  } catch (err) {
    if (err instanceof BreakGlassError) {
      process.stderr.write(`grenz: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
  breakGlass.purgeExpired(Date.now());

  // Taint-flow facts: ephemeral, in-memory source-action memory per token-holder.
  // No persistence, no fail-closed load — session-scoped by design.
  const flowFacts = new FlowFactStore();

  // Session pin facts: ephemeral, in-memory target-unit memory per token-holder.
  // Session-scoped by design; NOT cleared on --watch reload (pins are
  // observations, like flow facts).
  const pinFacts = new PinStore();

  const serverDeps = {
    config,
    agentStore,
    configPath: paths.config,
    configWriteLock,
    policy,
    policyStore,
    policyHistory,
    policyPath: paths.policy,
    vault,
    log,
    broker,
    approvalMemory,
    notifier,
    adminToken,
    tokenStore,
    revocations,
    delegations,
    grants,
    breakGlass,
    flowFacts,
    pinFacts,
    canaryPolicy,
    canaryStore,
    policyDistribution,
    fleetRevocations: fleetRevocations ?? undefined,
    revocationDistribution,
    emit,
    shadow,
    execGuard: config.exec_guard,
  };

  // --- Bash guard (opt-in) --------------------------------------------------
  // Load the parser BEFORE the listener accepts anything. `grenz hook` denies
  // when the parser is missing, so a lazy load would turn the first few guarded
  // commands into spurious denials; a failure here refuses to start instead.
  if (config.exec_guard) {
    try {
      await loadBashParser();
    } catch (err) {
      process.stderr.write(`grenz: could not load the bash command parser — ${(err as Error).message}\n`);
      return 1;
    }
    // Surface the exec-grant findings HERE rather than leaving them to
    // `grenz policy lint`. Every other lint rule is advisory authoring quality
    // and waits to be asked for; the deny-order one is different — it reports a
    // rule the operator believes is enforcing that an agent can step around by
    // reordering arguments. A check nobody runs is not a mitigation, and the
    // operator is standing right here.
    for (const f of lintExec(policy)) {
      emit(`[bash] ${f.clause} "${f.pattern}": ${f.detail}`);
    }
  }

  // --- Socket mode (opt-in) -------------------------------------------------
  // With `listen.socket` set, AGENT routes move to a unix socket reachable only
  // by this OS user, and the TCP listener keeps only the admin plane. Every
  // failure here refuses to start rather than silently falling back to TCP —
  // an operator who asked for socket mode must never get TCP by surprise.
  let socketStarted: ReturnType<typeof startSocketServer> | null = null;
  // The published path, which is NOT the one the server was bound to: the
  // listener is staged on a private name and linked into place. Anything shown
  // to an operator must be this, never `socketStarted.url`.
  let socketPublishedPath: string | null = null;
  if (config.listen.socket !== undefined) {
    const resolved = resolveSocketPath(config.listen.socket, paths.home);
    if (!resolved.ok) {
      process.stderr.write(`grenz: ${resolved.error}\n`);
      return 1;
    }
    const dir = prepareSocketDir(resolved.path);
    if (!dir.ok) {
      process.stderr.write(`grenz: ${dir.error}\n`);
      return 1;
    }
    // link(2) is the mutex: bindWithRecovery listens on a private temp path and
    // publishes it atomically, so a second proxy can never take over a live one.
    // It binds where it is told — `p`, not `resolved.path`.
    const bound = await bindWithRecovery(resolved.path, (p) => startSocketServer(serverDeps, p));
    if (!bound.ok) {
      process.stderr.write(`grenz: ${bound.error}\n`);
      return 1;
    }
    socketStarted = bound.server;
    socketPublishedPath = resolved.path;
    finalizeSocket(resolved.path);
  }

  // In socket mode this listener serves the admin plane only.
  const started = startServer({ ...serverDeps, agentRoutesEnabled: socketStarted === null });

  // Hot-reload: watch policy.yaml and swap the live policy on a successful
  // recompile. A malformed policy is rejected (the live one stays). Skipped
  // when policy is pulled from the plane (the remote is authoritative).
  let policyWatcher: FSWatcher | null = null;
  let watchLine = "off";
  if (watch && config.policy_source) {
    watchLine = "off (remote policy source)";
    emit(`[policy] --watch ignored: policy is pulled from ${config.policy_source.url}`);
  } else if (watch) {
    watchLine = "on";
    let reloadTimer: ReturnType<typeof setTimeout> | null = null;
    policyWatcher = fsWatch(paths.policy, () => {
      // Debounce: editors emit several events per save.
      if (reloadTimer) clearTimeout(reloadTimer);
      reloadTimer = setTimeout(() => {
        void Bun.file(paths.policy)
          .text()
          .then((text) => {
            const outcome = policyStore.reload(text);
            if (outcome.ok) {
              policyHistory.record(text, Date.now());
              approvalMemory?.clear(); // a policy change invalidates remembered decisions
              emit(`[policy] reloaded (${outcome.grants} grants, was ${outcome.previousGrants})`);
            } else {
              emit(`[policy] reload REJECTED: ${outcome.error} — keeping current`);
            }
          })
          .catch(() => emit(`[policy] reload REJECTED: could not read ${paths.policy} — keeping current`));
      }, 150);
    });
  }

  // Signed distribution: re-pull on a jittered interval so a fleet converges on
  // a newly signed policy without a restart. Every accepted bundle goes through
  // the same policyStore.reload() swap --watch uses; a rejected one leaves the
  // live policy in force.
  let refreshTimer: ReturnType<typeof setTimeout> | null = null;
  let distLine = config.policy_source ? (signedMode ? "signed" : "unsigned (pin a key!)") : "local";
  // Both modes. Unsigned distribution used to skip this block entirely, so
  // `refresh_seconds` and `on_stale` were inert for every proxy without a
  // pinned key — including every proxy `grenz connect` sets up. The config
  // promised a refresh that never ran and a fail-closed that never fired.
  if (config.policy_source && orgTokenForRefresh) {
    const src = config.policy_source;
    const store = versionStore;
    const orgToken = orgTokenForRefresh;
    const refresh = (): Promise<unknown> =>
      signedMode && store
        ? refreshOnce({
        fetchBundle: (minVersion) => fetchSignedPolicy(src.url, orgToken, pinnedKeys, minVersion),
        policyStore,
        versionStore: store,
        state: policyDistribution,
        now: () => Date.now(),
        emit,
        onAdopted: (yaml, at) => {
          // Records ONLY the default policy YAML — per-profile changes are
          // intentionally not captured here (fast-follow, out of S3-P scope), so
          // `grenz policy` history reflects the default, not profile edits.
          policyHistory.record(yaml, at);
          approvalMemory?.clear(); // a policy change invalidates remembered decisions
        },
      })
        : refreshUnsignedOnce({
            fetchPolicy: () => fetchRemotePolicy(src.url, orgToken),
            policyStore,
            state: policyDistribution,
            now: () => Date.now(),
            digestOf: policyDigest,
            emit,
            onAdopted: (yaml: string, at: number) => {
              policyHistory.record(yaml, at);
              approvalMemory?.clear();
            },
          });

    // Staleness: when the running policy has not been re-verified inside
    // max_age_seconds, warn — or, if the operator opted into fail_closed, swap
    // to a zero-grant policy so the proxy denies rather than enforce rules it
    // can no longer confirm are current. A later successful refresh restores it.
    let closedForStaleness = false;
    const checkStaleness = (): void => {
      if (!isStale(policyDistribution, src.max_age_seconds, Date.now())) {
        closedForStaleness = false;
        return;
      }
      if (src.on_stale !== "fail_closed") {
        emit(`[policy] STALE: no verified pull in ${src.max_age_seconds}s — still enforcing the last-good policy`);
        return;
      }
      if (closedForStaleness) return;
      const denyAll = compilePolicyYaml(denyAllYaml(policy.agent, policy.onBehalfOf));
      if (!denyAll.ok) {
        emit(`[policy] STALE + on_stale=fail_closed: could not build the deny-all policy (${denyAll.error}) — keeping current`);
        return;
      }
      policyStore.closeAll(denyAll.policy);
      closedForStaleness = true;
      emit(
        `[policy] STALE + on_stale=fail_closed: no verified pull in ${src.max_age_seconds}s — swapped to DENY-ALL ` +
          `until a fresh ${signedMode ? "signed " : ""}policy arrives`,
      );
    };

    if (src.refresh_seconds > 0) {
      const base = src.refresh_seconds * 1000;
      // Jitter +/-10% so a restarted fleet does not stampede the plane in lockstep.
      const nextDelay = (): number => Math.round(base * (0.9 + Math.random() * 0.2));
      const tick = (): void => {
        refreshTimer = setTimeout(() => {
          void refresh()
            .catch(() => emit("[policy] refresh REJECTED: unexpected error — keeping current"))
            .finally(() => {
              checkStaleness();
              tick();
            });
        }, nextDelay());
      };
      tick();
      distLine = `${signedMode ? "signed" : "unsigned (pin a key!)"} (refresh ${src.refresh_seconds}s ±10%)`;
    }
    checkStaleness(); // a proxy that boots without a verified pull is stale immediately
  }

  // Signed revocation refresh: own, shorter clock. Every accepted set persists;
  // a rejected pull keeps the cached set enforced. Fail-closed staleness denies
  // ALL requests via revocationDistribution.staleClosed (read by the gate).
  let revocationTimer: ReturnType<typeof setTimeout> | null = null;
  let revDistLine = "off";
  if (fleetRevocations && revSrc?.revocation_url && orgTokenForRefresh) {
    const store = fleetRevocations;
    const url = revSrc.revocation_url;
    const orgToken = orgTokenForRefresh;
    const revRefresh = (): Promise<unknown> =>
      refreshRevocationsOnce({
        fetchSet: (minVersion) => fetchRevocationSet(url, orgToken, pinnedKeys, minVersion),
        store,
        state: revocationDistribution,
        now: () => Date.now(),
        emit,
      });

    let revWarned = false;
    const checkRevocationStaleness = (): void => {
      if (!isRevocationStale(revocationDistribution, revSrc.revocation_max_age_seconds, Date.now())) {
        revocationDistribution.staleClosed = false;
        revWarned = false;
        return;
      }
      if (revSrc.on_revocation_stale !== "fail_closed") {
        if (!revWarned) {
          emit(
            `[revocation] STALE: no fresh signed set — still enforcing the cached ${revocationDistribution.count} ` +
              `cut-off agent(s) (a set revoked since the last pull would NOT yet apply here)`,
          );
          revWarned = true;
        }
        return;
      }
      if (revocationDistribution.staleClosed) return;
      revocationDistribution.staleClosed = true;
      emit(
        "[revocation] STALE + on_revocation_stale=fail_closed: denying ALL requests until a fresh signed set arrives",
      );
    };

    if (revSrc.revocation_refresh_seconds > 0) {
      const base = revSrc.revocation_refresh_seconds * 1000;
      // Jitter +/-10% so a restarted fleet does not stampede the plane in lockstep.
      const nextDelay = (): number => Math.round(base * (0.9 + Math.random() * 0.2));
      const tick = (): void => {
        revocationTimer = setTimeout(() => {
          void revRefresh()
            .catch(() => emit("[revocation] refresh REJECTED: unexpected error — keeping the cached set"))
            .finally(() => {
              checkRevocationStaleness();
              tick();
            });
        }, nextDelay());
      };
      tick();
      revDistLine = `signed (refresh ${revSrc.revocation_refresh_seconds}s ±10%, ${revSrc.on_revocation_stale})`;
    } else {
      revDistLine = `signed (startup only, ${revSrc.on_revocation_stale})`;
    }
    checkRevocationStaleness(); // a proxy that boots stale (or with an expired set) closes immediately under fail_closed
  }

  // Gate 4: opt-in anonymized telemetry (aggregate tool/action counts only).
  let reporter: StatsReporter = nullReporter;
  let telemetryTimer: ReturnType<typeof setInterval> | null = null;
  let telemetryFirstTimer: ReturnType<typeof setTimeout> | null = null;
  let telemetryLine = "off";
  if (config.telemetry?.enabled) {
    const orgToken = await localVault.get(config.telemetry.org_token_key);
    if (!orgToken) {
      process.stderr.write(
        `grenz: telemetry enabled but vault key "${config.telemetry.org_token_key}" is missing — telemetry off\n`,
      );
    } else {
      reporter = new CloudStatsReporter(config.telemetry.endpoint, orgToken, emit);
      const intervalMs = config.telemetry.interval_seconds * 1000;
      const window = new StatsWindow(log, reporter, Date.now());
      const flush = (): void => void window.flush(Date.now());
      // interval_seconds goes up to a day, and the timer only fires after a
      // full one — so a correct setup can look broken for an hour while its
      // first report is still pending. Send an early one when the interval is
      // long enough for that to matter.
      if (intervalMs > FIRST_REPORT_MS) telemetryFirstTimer = setTimeout(flush, FIRST_REPORT_MS);
      telemetryTimer = setInterval(flush, intervalMs);
      telemetryLine = `on (${config.telemetry.interval_seconds}s → ${config.telemetry.endpoint})`;
    }
  }

  // Gate: live risk signal — emit an alert when an agent crosses into
  // elevated/high (denial spikes, probing) since the last check.
  const RISK_WINDOW_MS = 10 * 60 * 1000;
  const riskLevels = new Map<string, string>();
  const riskTimer = setInterval(() => {
    const since = Date.now() - RISK_WINDOW_MS;
    // Read the LIVE agent set so a console-minted agent is scored too (else it
    // would get no denial-spike alert until the next restart).
    for (const agent of agentStore.current) {
      const r = scoreRisk(log.agentActivity(agent.id, since));
      const prev = riskLevels.get(agent.id) ?? "low";
      if (r.level !== "low" && r.level !== prev) {
        // Detect → respond: a high score is when you reach for the kill-switch.
        const hint = r.level === "high" ? ` — cut it off: grenz revoke ${agent.id}` : "";
        emit(`[risk] ${agent.id} ${r.level} (score ${r.score}): ${r.reasons.join(", ")}${hint}`);
      }
      riskLevels.set(agent.id, r.level);
    }
  }, 60_000);

  const budget = policy.maxActionsPerHour === null ? "unlimited" : `${policy.maxActionsPerHour}/hr`;
  const dlpLine = policy.dlp?.scanBodies ? `on (${policy.dlp.onMatch})` : "off";
  const revokedCount = revocations.list().length;
  const revokedLine = revokedCount === 0 ? "none" : `${revokedCount} agent(s) cut off`;
  const delegationCount = delegations.list(Date.now()).length;
  const delegationLine = delegationCount === 0 ? "none active" : `${delegationCount} active`;
  const grantCount = grants.list(Date.now()).length;
  const grantLine = grantCount === 0 ? "none active" : `${grantCount} active`;
  const upstreamList = Object.entries(config.upstreams)
    .map(([name, u]) => `${name} (${u.type})`)
    .join(", ") || "(none configured)";
  const notifyLine =
    notifier instanceof RelayChannel
      ? `relay (${config.relay?.url})`
      : notifier === nullNotifier
        ? "off (set vault key slack_webhook to enable)"
        : "slack";

  if (shadow) {
    process.stdout.write(
      [
        ``,
        `  ⚠ SHADOW MODE — policy denials are NOT enforced.`,
        `    Requests that would be denied or need approval are forwarded and`,
        `    logged as would-block. Auth, revocation, delegation, DLP, budget,`,
        `    and vault gates remain enforced. Drop --shadow to enforce policy.`,
        ``,
      ].join("\n") + "\n",
    );
  }

  process.stdout.write(
    [
      ``,
      ...(socketStarted
        ? [
            `  Grenz agents  on ${socketStarted.url}  (your OS user only)`,
            `         admin   on ${started.url}`,
          ]
        : [`  Grenz listening on ${started.url}`]),
      `  agent:        ${policy.agent}`,
      `  on behalf of: ${policy.onBehalfOf}`,
      `  upstreams:    ${upstreamList}`,
      `  secrets:      ${secretsLine}`,
      `  budget:       ${budget}`,
      `  approvals:    ttl ${config.approvals.ttl_seconds}s${approvalHoldNote(
        config.approvals.ttl_seconds,
      )}, notify ${notifyLine}, remember ${
        config.approvals.remember_seconds > 0 ? `${config.approvals.remember_seconds}s` : "off"
      }`,
      `  dlp:          ${dlpLine}`,
      `  shadow:       ${shadow ? "ON — policy NOT enforced" : "off"}`,
      `  canary:       ${canaryLine}`,
      `  pins:         ${policy.pins.length > 0 ? `${policy.pins.length} rule(s)` : "off"}`,
      `  policy watch: ${watchLine}`,
      `  policy dist:  ${
        signedMode
          ? `${distLine} — running v${policyDistribution.version || "?"} (${policyDistribution.digest || "not pulled"})`
          : distLine
      }`,
      `  policy hist:  ${policyHistory.list().length} snapshot(s)`,
      `  fleet revoke: ${
        fleetRevocations
          ? `${revDistLine} — v${revocationDistribution.version || "?"} (${revocationDistribution.count} cut off)`
          : "off"
      }`,
      `  admins:       ${tokenStore.list().filter((t) => t.revokedAt === null).length} named + bootstrap`,
      `  revoked:      ${revokedLine}`,
      `  delegations:  ${delegationLine}`,
      `  grants:       ${grantLine}`,
      `  break-glass:  ${breakGlass.list(Date.now()).length} active window(s)`,
      `  telemetry:    ${telemetryLine}`,
      `  log:          ${paths.db}`,
      ``,
      ...(socketStarted && socketPublishedPath
        ? [
            `  Requests: curl --unix-socket ${socketPublishedPath} http://localhost/u/<upstream>/...`,
            `            (agent routes on the TCP listener answer 403 wrong_listener)`,
          ]
        : [`  Requests: ${started.url}/u/<upstream>/...   Health: ${started.url}/healthz`]),
      `  Console:  ${started.url}/console/*  (admin token: ${paths.adminToken})`,
      `  Approvals: grenz approvals | grenz approve <id> | grenz deny <id>`,
      `  Kill-switch: grenz revoke <agent> | grenz restore <agent> | grenz revocations`,
      `  Delegation: grenz delegate <agent> --actions <a,b> | grenz delegations`,
      `  Grants: grenz grant <agent> --actions <a,b> | grenz grants`,
      `  Ctrl-C to stop.`,
      ``,
    ].join("\n") + "\n",
  );

  let stopping = false;
  const shutdown = async (): Promise<void> => {
    if (stopping) return;
    stopping = true;
    process.stdout.write("\ngrenz: shutting down\n");
    // Release held approvals (→ expire → DENY), then let the event loop flush
    // those responses to the waiting clients BEFORE stopping the server/process.
    broker.drain();
    if (policyWatcher) policyWatcher.close();
    clearInterval(riskTimer);
    if (refreshTimer) clearTimeout(refreshTimer);
    if (revocationTimer) clearTimeout(revocationTimer);
    if (telemetryFirstTimer) clearTimeout(telemetryFirstTimer);
    if (telemetryTimer) clearInterval(telemetryTimer);
    await new Promise((resolve) => setTimeout(resolve, 150));
    // Stop the socket listener first — a graceful stop removes the socket file,
    // so the next start finds a clean path.
    if (socketStarted) socketStarted.stop();
    started.stop();
    log.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());

  // Keep the process alive; Bun.serve holds the event loop open.
  await new Promise<void>(() => {});
  return 0;
}
