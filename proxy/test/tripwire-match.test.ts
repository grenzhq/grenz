import { test, expect, describe } from "bun:test";
import { matchTripwire } from "../src/policy/tripwire.ts";
import { compilePolicyYaml, type CompiledTripwire } from "../src/policy/compile.ts";

function wires(yaml: string): readonly CompiledTripwire[] {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\n${yaml}`);
  if (!r.ok) throw new Error(r.error);
  return r.policy.tripwires;
}

const W = wires(`
tripwires:
  - action: "*:admin"
  - action: "*:delete"
    targets: ["prod-*"]
`);

describe("matchTripwire", () => {
  test("unscoped tripwire matches its action, any target", () => {
    expect(matchTripwire(W, "secrets:admin", "/anything")!.action.source).toBe("*:admin");
    expect(matchTripwire(W, "secrets:admin", null)!.action.source).toBe("*:admin");
  });

  test("scoped tripwire matches only its target", () => {
    expect(matchTripwire(W, "repo:delete", "prod-db")!.action.source).toBe("*:delete");
    expect(matchTripwire(W, "repo:delete", "staging-db")).toBeNull();
  });

  test("null target + scoped tripwire -> matches (reachability, fail-loud)", () => {
    expect(matchTripwire(W, "repo:delete", null)!.action.source).toBe("*:delete");
  });

  test("no tripwire for the action -> null", () => {
    expect(matchTripwire(W, "repo:read", "/x")).toBeNull();
  });
});
