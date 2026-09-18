/**
 * Capabilities — the plain-language view of a policy's grants.
 *
 * People do not think "exec:git with targets git push*". They think "let it
 * commit, but ask me before it publishes". This module is the two-way map
 * between those vocabularies. It is pure and synchronous, and it reads and
 * rewrites the SAME editor-shaped grants the policy page already round-trips,
 * so every write still goes through the proxy's real compiler and can only be
 * applied if it compiles.
 *
 * Three rules govern it, and they are the difference between a friendly view
 * and a dishonest one:
 *
 *  1. **Nothing is hidden and nothing is mislabelled.** Claiming happens per
 *     TARGET, not per rule, because one rule's targets can belong to different
 *     capabilities — the real bash policy allows `git status*` and
 *     `git -c credential.helper=* fetch *` in the same rule. Whatever no
 *     capability can name comes back as a leftover, shown as written.
 *  2. **Nothing is widened by accident.** Changing a capability's state moves
 *     its existing targets between clauses verbatim, so a grant narrowed to
 *     four folders stays narrowed to four folders.
 *  3. **Blocking is absolute or it is nothing.** A target-scoped deny can be
 *     stepped around by reordering arguments, so blocking never writes one.
 *     A whole binary is blocked with an unscoped `exec:<binary>`; part of a
 *     binary (`git push`) is blocked by REMOVING its allow, which drops it to
 *     the engine's deny-by-default floor — unevadable, because it is the floor.
 */

export type Clause = "allow" | "require_approval" | "deny";
export type CapState = "allow" | "ask" | "block";

const CLAUSES: readonly Clause[] = ["allow", "require_approval", "deny"];

const STATE_OF_CLAUSE: Record<Clause, CapState> = {
  allow: "allow",
  require_approval: "ask",
  deny: "block",
};

export type CapGroup = "code" | "git" | "machine" | "never";

export interface Capability {
  readonly id: string;
  readonly group: CapGroup;
  readonly name: string;
  readonly description: string;
  /** Any rule for these exec binaries belongs here, whatever its targets. */
  readonly binaries?: readonly string[];
  /** A target beginning with one of these belongs here. The binary is the
   *  prefix's first word, so `"git push"` claims `exec:git` / `git push*`. */
  readonly prefixes?: readonly string[];
}

export const GROUPS: ReadonlyArray<{ id: CapGroup; title: string; note: string }> = [
  { id: "code", title: "Your code", note: "reading and building, all on this machine" },
  { id: "git", title: "Git and GitHub", note: "split by whether the work leaves your machine" },
  { id: "machine", title: "Your machine", note: "outside the project, or outside this computer" },
  { id: "never", title: "Never", note: "refused outright — a temporary grant cannot reopen these" },
];

/**
 * The bash catalogue.
 *
 * Editorial, not derived: which commands belong together is a judgement about
 * consequences, and it is the whole value of this screen. The split points that
 * earn their complexity are `git` (does the work leave your machine?) and `gh`
 * (does it change something other people see?); everything else groups by
 * binary, where the binary already names the consequence.
 */
export const BASH_CAPABILITIES: readonly Capability[] = [
  {
    id: "read",
    group: "code",
    name: "Read and search files",
    description: "Open, list and search files.",
    binaries: [
      "cat", "ls", "head", "tail", "grep", "rg", "find", "wc", "sed", "diff",
      "du", "sort", "uniq", "cut", "tr", "jq", "shasum", "which", "echo",
      "printf", "date", "pgrep", "true",
    ],
  },
  {
    id: "build",
    group: "code",
    name: "Run tests and builds",
    description: "Test runners, bundlers and type checks.",
    binaries: ["bun", "bunx", "npm", "npx", "pnpm", "yarn", "make", "tsc"],
  },
  {
    id: "navigate",
    group: "code",
    name: "Move around the project",
    description: "Change folder, make a folder.",
    binaries: ["cd", "mkdir", "pwd"],
  },
  {
    id: "git-local",
    group: "git",
    name: "Commit locally",
    description: "Stage, commit, branch, stash, check out. Nothing is published.",
    prefixes: [
      "git status", "git diff", "git log", "git show", "git branch", "git tag",
      "git remote", "git rev-parse", "git ls-files", "git ls-remote", "git fetch",
      "git pull", "git add", "git commit", "git checkout", "git switch",
      "git stash", "git format-patch", "git blame", "git describe",
    ],
  },
  {
    id: "git-publish",
    group: "git",
    name: "Publish and rewrite history",
    description:
      "Push, reset, rebase, clean — changes other people can see, or work you cannot get back.",
    prefixes: ["git push", "git reset", "git rebase", "git clean", "git filter-branch"],
  },
  {
    id: "gh-read",
    group: "git",
    name: "Read and open pull requests",
    description: "View, list, create, comment, check CI.",
    prefixes: [
      "gh auth", "gh pr view", "gh pr list", "gh pr create", "gh pr edit",
      "gh pr checks", "gh pr diff", "gh issue", "gh run", "gh api",
    ],
  },
  {
    id: "gh-write",
    group: "git",
    name: "Merge PRs and change repositories",
    description: "Merge, rename, delete, change settings.",
    prefixes: ["gh pr merge", "gh pr close", "gh repo", "gh release", "gh secret"],
  },
  {
    id: "files",
    group: "machine",
    name: "Delete, move and copy files",
    description: "Anywhere the agent can reach, not only the project.",
    binaries: ["rm", "mv", "cp", "rmdir", "truncate"],
  },
  {
    id: "network",
    group: "machine",
    name: "Reach the network",
    description: "Download or send data.",
    binaries: ["curl", "wget", "nc", "ftp"],
  },
  {
    id: "processes",
    group: "machine",
    name: "Stop running processes",
    description: "Kill a process by id or by name.",
    binaries: ["kill", "pkill", "killall"],
  },
  {
    id: "admin",
    group: "never",
    name: "Administrator access",
    description: "Everything the agent could do becomes everything you can do.",
    binaries: ["sudo", "doas", "su"],
  },
  {
    id: "remote",
    group: "never",
    name: "Connect to other machines",
    description: "A way off this computer entirely.",
    binaries: ["ssh", "scp", "sftp", "rsync"],
  },
];

/** One grant as the policy editor round-trips it. Mirrors `EditorGrant` in
 *  `proxy/src/policy/editor.ts`; entries are a bare action pattern or the
 *  target-scoped object form. */
export type Entry = string | Record<string, unknown>;

export interface EditorGrant {
  tool: string;
  allow: Entry[];
  require_approval: Entry[];
  deny: Entry[];
}

interface NormalRule {
  readonly clause: Clause;
  readonly index: number;
  readonly action: string;
  /** null = unscoped: the rule matches any target. */
  readonly targets: readonly string[] | null;
  readonly entry: Entry;
}

function normalize(grant: EditorGrant): NormalRule[] {
  const out: NormalRule[] = [];
  for (const clause of CLAUSES) {
    const list = grant[clause] ?? [];
    list.forEach((entry, index) => {
      if (typeof entry === "string") {
        out.push({ clause, index, action: entry, targets: null, entry });
        return;
      }
      const action = typeof entry.action === "string" ? entry.action : "";
      if (!action) return;
      const targets = Array.isArray(entry.targets)
        ? entry.targets.filter((t): t is string => typeof t === "string")
        : null;
      out.push({ clause, index, action, targets, entry });
    });
  }
  return out;
}

/** `exec:git` → `git`. A non-exec action has no binary, so no bash capability
 *  can claim it and it falls through to leftovers. */
function binaryOf(action: string): string | null {
  const m = /^exec:(.+)$/.exec(action);
  return m ? (m[1] ?? null) : null;
}

/** What this capability takes from one rule: the whole thing, some of its
 *  targets, or nothing. */
type Claim =
  | { kind: "none" }
  | { kind: "whole" }
  | { kind: "targets"; targets: readonly string[] };

function claimOf(cap: Capability, rule: NormalRule): Claim {
  const binary = binaryOf(rule.action);
  if (binary === null) return { kind: "none" };
  if (cap.binaries?.includes(binary)) return { kind: "whole" };
  if (!cap.prefixes) return { kind: "none" };

  const mine = cap.prefixes.filter((p) => p.split(" ")[0] === binary);
  if (mine.length === 0) return { kind: "none" };
  // An unscoped `exec:git` is every git subcommand at once — broader than any
  // one capability, so no capability claims it; it surfaces as a leftover,
  // which is exactly the rule an operator should be looking at.
  if (rule.targets === null) return { kind: "none" };

  const hit = rule.targets.filter((t) => mine.some((p) => t.startsWith(p)));
  if (hit.length === 0) return { kind: "none" };
  return { kind: "targets", targets: hit };
}

/** The self-anchored forms a binary capability generates: `head` and `head *`.
 *  A rule whose targets are only these narrows nothing — it just pins the
 *  basename, which every allow must do anyway. */
function isTrivialTarget(binary: string, target: string): boolean {
  const t = target.trim();
  return t === binary || t === `${binary} *` || t === `${binary}*`;
}

export interface CapabilityRow {
  readonly cap: Capability;
  readonly state: CapState;
  /** No rule covers this capability, so it sits at the deny-by-default floor.
   *  `state` is still "block" — the difference is that nothing was written. */
  readonly present: boolean;
  /** Its rules span more than one of allow / ask / block. */
  readonly mixed: boolean;
  /** Distinct target globs beyond the plain `<binary>` forms; 0 = not narrowed. */
  readonly narrowedTo: number;
  /** What this capability actually covers in this policy, for disclosure: the
   *  binaries for a whole-binary capability, the command shapes for one that
   *  claims a slice of a binary — because "git" is not a useful thing to show
   *  under a row that means "commit, but do not publish". */
  readonly commands: readonly string[];
  readonly ruleCount: number;
}

export interface LeftoverRule {
  readonly clause: Clause;
  readonly state: CapState;
  readonly action: string;
  readonly targets: readonly string[];
}

export interface CapabilityView {
  readonly rows: readonly CapabilityRow[];
  /** Rules, or parts of rules, no capability could name. Shown as written. */
  readonly leftovers: readonly LeftoverRule[];
}

/** Read a bash grant as capabilities plus whatever could not be named. */
export function readCapabilities(
  grant: EditorGrant | undefined,
  catalogue: readonly Capability[] = BASH_CAPABILITIES,
): CapabilityView {
  const rules = grant ? normalize(grant) : [];
  // Per rule, which of its targets some capability took. A rule with no entry
  // here was never claimed at all.
  const takenWhole = new Set<NormalRule>();
  const takenTargets = new Map<NormalRule, Set<string>>();

  const rows = catalogue.map<CapabilityRow>((cap) => {
    const mine: Array<{ rule: NormalRule; targets: readonly string[] | null }> = [];
    for (const rule of rules) {
      const claim = claimOf(cap, rule);
      if (claim.kind === "none") continue;
      if (claim.kind === "whole") {
        takenWhole.add(rule);
        mine.push({ rule, targets: rule.targets });
      } else {
        const seen = takenTargets.get(rule) ?? new Set<string>();
        for (const t of claim.targets) seen.add(t);
        takenTargets.set(rule, seen);
        mine.push({ rule, targets: claim.targets });
      }
    }

    if (mine.length === 0) {
      return {
        cap,
        state: "block",
        present: false,
        mixed: false,
        narrowedTo: 0,
        commands: [],
        ruleCount: 0,
      };
    }

    const clausesSeen = new Set(mine.map((m) => m.rule.clause));
    // Several clauses at once: report the most permissive one present and flag
    // it. Picking a single tidy state would be the dishonest option.
    const clause = CLAUSES.find((c) => clausesSeen.has(c)) ?? "allow";

    const narrowing = new Set<string>();
    for (const m of mine) {
      const binary = binaryOf(m.rule.action);
      if (m.targets === null || binary === null) continue;
      for (const t of m.targets) if (!isTrivialTarget(binary, t)) narrowing.add(t);
    }

    const commands = cap.prefixes
      ? Array.from(new Set(mine.flatMap((m) => m.targets ?? []))).sort()
      : Array.from(
          new Set(mine.map((m) => binaryOf(m.rule.action)).filter((b): b is string => b !== null)),
        ).sort();

    return {
      cap,
      state: STATE_OF_CLAUSE[clause],
      present: true,
      mixed: clausesSeen.size > 1,
      // A prefix capability's targets are specific by nature; calling that
      // "narrowed" would tag every git row forever and mean nothing.
      narrowedTo: cap.prefixes ? 0 : narrowing.size,
      commands,
      ruleCount: mine.length,
    };
  });

  const leftovers: LeftoverRule[] = [];
  for (const rule of rules) {
    if (takenWhole.has(rule)) continue;
    const taken = takenTargets.get(rule);
    if (!taken) {
      leftovers.push({
        clause: rule.clause,
        state: STATE_OF_CLAUSE[rule.clause],
        action: rule.action,
        targets: rule.targets ?? [],
      });
      continue;
    }
    const rest = (rule.targets ?? []).filter((t) => !taken.has(t));
    if (rest.length === 0) continue;
    leftovers.push({
      clause: rule.clause,
      state: STATE_OF_CLAUSE[rule.clause],
      action: rule.action,
      targets: rest,
    });
  }

  return { rows, leftovers };
}

function cloneGrant(grant: EditorGrant): EditorGrant {
  return {
    tool: grant.tool,
    allow: [...(grant.allow ?? [])],
    require_approval: [...(grant.require_approval ?? [])],
    deny: [...(grant.deny ?? [])],
  };
}

/** The rules a capability gets when it has none yet and is being switched on.
 *  Allows are anchored to a target — `head` AND `head *`, because a glob's
 *  space is literal and `head *` alone misses a bare `head` at the end of a
 *  pipeline. */
function synthesize(cap: Capability, state: CapState): Entry[] {
  if (state === "block") return [];
  if (cap.binaries) {
    return cap.binaries.map((b) => ({ action: `exec:${b}`, targets: [b, `${b} *`] }));
  }
  const byBinary = new Map<string, string[]>();
  for (const p of cap.prefixes ?? []) {
    const binary = p.split(" ")[0];
    if (!binary) continue;
    byBinary.set(binary, [...(byBinary.get(binary) ?? []), `${p}*`]);
  }
  return Array.from(byBinary, ([binary, targets]) => ({ action: `exec:${binary}`, targets }));
}

/**
 * Move a capability to a new state.
 *
 * Existing targets are moved, not rewritten, so scope survives the change.
 * Blocking is the asymmetric case, per rule 3 at the top of this file: a whole
 * binary gets an unscoped deny (absolute, and a temporary grant cannot reopen
 * it); part of a binary simply loses its allow and falls to deny-by-default,
 * because a `git push*` deny rule would be evadable by argument order and would
 * be worse than no rule at all.
 */
export function applyCapability(
  grant: EditorGrant,
  capId: string,
  state: CapState,
  catalogue: readonly Capability[] = BASH_CAPABILITIES,
): EditorGrant {
  const cap = catalogue.find((c) => c.id === capId);
  if (!cap) return grant;

  const rules = normalize(grant);
  const next = cloneGrant(grant);
  const moved: Entry[] = [];
  const dropped = new Map<Clause, Set<number>>(CLAUSES.map((c) => [c, new Set<number>()]));
  const rewritten = new Map<Clause, Map<number, Entry>>(CLAUSES.map((c) => [c, new Map()]));

  for (const rule of rules) {
    const claim = claimOf(cap, rule);
    if (claim.kind === "none") continue;

    if (claim.kind === "whole") {
      dropped.get(rule.clause)!.add(rule.index);
      if (state !== "block") moved.push(rule.entry);
      continue;
    }

    // Partial: the rule keeps the targets this capability did not claim, and
    // the claimed ones travel to the new clause as a rule of their own.
    const rest = (rule.targets ?? []).filter((t) => !claim.targets.includes(t));
    if (rest.length === 0) dropped.get(rule.clause)!.add(rule.index);
    else rewritten.get(rule.clause)!.set(rule.index, { ...(rule.entry as object), targets: rest });
    if (state !== "block") moved.push({ action: rule.action, targets: [...claim.targets] });
  }

  for (const clause of CLAUSES) {
    const drop = dropped.get(clause)!;
    const edits = rewritten.get(clause)!;
    next[clause] = next[clause]
      .map((e, i) => edits.get(i) ?? e)
      .filter((_, i) => !drop.has(i));
  }

  if (state === "block") {
    // Only a whole-binary capability gets a written deny; a slice of a binary
    // is blocked by its absence, which the engine already treats as a refusal.
    if (cap.binaries) {
      const existing = new Set(
        next.deny.filter((e): e is string => typeof e === "string"),
      );
      for (const b of cap.binaries) {
        const pattern = `exec:${b}`;
        if (!existing.has(pattern)) next.deny.push(pattern);
      }
    }
    return next;
  }

  const clause: Clause = state === "allow" ? "allow" : "require_approval";
  next[clause].push(...(moved.length > 0 ? moved : synthesize(cap, state)));
  return next;
}

/** Blocking a whole binary throws away its target scoping — worth confirming. */
export function losesScope(row: CapabilityRow, state: CapState): boolean {
  return state === "block" && row.present && row.narrowedTo > 0 && !row.cap.prefixes;
}
