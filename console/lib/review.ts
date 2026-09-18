/**
 * Reading a request log as a proposed policy.
 *
 * The scariest moment in a permissioning tool is the empty editor: you are
 * asked to predict, in a syntax you just met, everything a program will ever
 * need. Grenz already records every request, so the first policy does not have
 * to be predicted — it can be read back off what the agent actually did while
 * the proxy watched (`grenz run --shadow`, which decides and records but
 * forwards regardless).
 *
 * This module turns that log into decisions a person can make. Pure and
 * synchronous; it proposes, and nothing is written until someone presses the
 * button.
 */

import {
  BASH_CAPABILITIES,
  capabilityFor,
  touchesSensitivePath,
  type CapState,
  type Capability,
} from "./capabilities";
import type { RequestRow } from "./types";

/** Why a capability was pulled to the top of the review. */
export type FlagReason = "never-group" | "sensitive-path" | "off-machine";

export interface ReviewItem {
  readonly cap: Capability;
  /** How many requests in the window landed here. */
  readonly count: number;
  /** Distinct targets, most recent first, for showing the evidence. */
  readonly examples: readonly string[];
  readonly suggested: CapState;
  /** Set when this one should be decided before the routine ones. */
  readonly flag: FlagReason | null;
  /** Plain-language reason, shown under the name. */
  readonly why: string;
  readonly lastSeen: number;
}

export interface Review {
  readonly flagged: readonly ReviewItem[];
  readonly routine: readonly ReviewItem[];
  readonly total: number;
  /** Requests no capability could name — they cannot be proposed, so they are
   *  counted and reported rather than quietly dropped. */
  readonly unrecognized: number;
}

const WHY: Record<FlagReason, string> = {
  "never-group":
    "There is no safe narrow version of this one: anything run this way can change the whole machine, and can undo Grenz itself.",
  "sensitive-path":
    "Your agent can read anything your user account can, not only this project — including keys and credentials. Most people narrow this.",
  "off-machine":
    "This is how work, and data, leaves this computer. Worth a deliberate answer rather than a default.",
};

function flagFor(cap: Capability, targets: readonly string[]): FlagReason | null {
  if (cap.group === "never") return "never-group";
  if (cap.id === "network" || cap.id === "remote") return "off-machine";
  // A read capability is the quiet one: it is granted broadly, sounds harmless,
  // and is the only one where the target is the whole story.
  if (targets.some(touchesSensitivePath)) return "sensitive-path";
  return null;
}

function routineWhy(cap: Capability, count: number): string {
  const times = count === 1 ? "once" : `${count} times`;
  return `Seen ${times}. ${cap.description}`;
}

/**
 * Group a request log by capability and propose a state for each.
 *
 * `requests` is the log newest-first, as the admin API returns it.
 */
export function buildReview(
  requests: readonly RequestRow[],
  catalogue: readonly Capability[] = BASH_CAPABILITIES,
): Review {
  const byCap = new Map<string, { cap: Capability; targets: string[]; count: number; lastSeen: number }>();
  let unrecognized = 0;

  for (const r of requests) {
    // The log splits an action into tool + action; the catalogue keys on the
    // action alone (`exec:git`), which is what the policy writes too.
    const cap = capabilityFor(r.action, r.target ?? "", catalogue);
    if (!cap) {
      unrecognized += 1;
      continue;
    }
    const slot = byCap.get(cap.id) ?? { cap, targets: [], count: 0, lastSeen: 0 };
    slot.count += 1;
    slot.lastSeen = Math.max(slot.lastSeen, r.ts);
    if (r.target && !slot.targets.includes(r.target)) slot.targets.push(r.target);
    byCap.set(cap.id, slot);
  }

  const items = Array.from(byCap.values()).map<ReviewItem>((slot) => {
    const flag = flagFor(slot.cap, slot.targets);
    // A flagged capability is proposed at its catalogue default, which for
    // everything flagged is `ask` or `block` — the review never proposes
    // widening something it just told you to look at.
    const suggested: CapState = flag === "sensitive-path" ? "ask" : slot.cap.defaultState;
    return {
      cap: slot.cap,
      count: slot.count,
      // Sensitive targets first: the evidence for the flag should be the
      // example you actually see.
      examples: [...slot.targets]
        .sort((a, b) => Number(touchesSensitivePath(b)) - Number(touchesSensitivePath(a)))
        .slice(0, 3),
      suggested,
      flag,
      why: flag ? (slot.cap.whenFlagged ?? WHY[flag]) : routineWhy(slot.cap, slot.count),
      lastSeen: slot.lastSeen,
    };
  });

  return {
    flagged: items.filter((i) => i.flag !== null).sort((a, b) => rank(a) - rank(b)),
    routine: items.filter((i) => i.flag === null).sort((a, b) => b.count - a.count),
    total: requests.length,
    unrecognized,
  };
}

/** Most alarming first. */
function rank(i: ReviewItem): number {
  if (i.flag === "never-group") return 0;
  if (i.flag === "off-machine") return 1;
  return 2;
}
