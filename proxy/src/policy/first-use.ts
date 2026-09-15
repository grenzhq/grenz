/**
 * Pure first-use scope test. Decides whether an action is gated by first-use —
 * i.e. whether it matches the policy's `only` list. The "has it been forwarded
 * before" question is a request-log read the proxy owns (like budget spend);
 * this comparator is deterministic given its inputs — no clock, no log, no
 * network.
 */
import type { CompiledFirstUse } from "./compile.ts";

export function firstUseInScope(firstUse: CompiledFirstUse, action: string): boolean {
  return firstUse.only.some((p) => p.re.test(action));
}
