/**
 * Pure tripwire matcher. Returns the first tripwire whose action pattern matches
 * `action` and — when the tripwire is target-scoped — whose targets match
 * `target`. A null target (worst-case reachability, used by `explain`) treats a
 * scoped tripwire as matchable: fail-loud, "this could trip". No clock, no I/O.
 */
import type { CompiledTripwire } from "./compile.ts";

export function matchTripwire(
  tripwires: readonly CompiledTripwire[],
  action: string,
  target: string | null,
): CompiledTripwire | null {
  for (const wire of tripwires) {
    if (!wire.action.re.test(action)) continue;
    if (wire.targets !== null && target !== null && !wire.targets.some((p) => p.re.test(target))) {
      continue;
    }
    return wire;
  }
  return null;
}
