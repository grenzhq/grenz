import { test, expect, describe } from "bun:test";
import { evaluatePin, evaluatePinBatch, pinUnitsFor, maxWithinMs } from "../src/pin/evaluate.ts";
import type { CompiledPin } from "../src/policy/compile.ts";
import type { PinFact } from "../src/pin/store.ts";

function pin(over: Partial<CompiledPin> = {}): CompiledPin {
  return {
    key: /^\/repos\/([^/]+\/[^/]+)/,
    on: [{ source: "*:write", re: /^[^:]+:write$/ }],
    effect: "require_approval",
    withinMs: 3600_000,
    ...over,
  };
}
const T = "/repos/acme/api/issues/1"; // unit acme/api
const T2 = "/repos/acme/payroll/issues/1"; // unit acme/payroll

describe("evaluatePin", () => {
  test("empty session -> first matching action is free (no hit)", () => {
    expect(evaluatePin([pin()], [], "issue:write", T, 5000)).toBeNull();
  });

  test("same unit already pinned -> no hit", () => {
    const facts: PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];
    expect(evaluatePin([pin()], facts, "issue:write", T, 5000)).toBeNull();
  });

  test("different unit while pinned -> hit", () => {
    const facts: PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];
    const hit = evaluatePin([pin()], facts, "issue:write", T2, 5000);
    expect(hit).toMatchObject({ effect: "require_approval", ruleIndex: 0, unit: "acme/payroll" });
  });

  test("action not in `on` -> pin-inert (no hit even off-unit)", () => {
    const facts: PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];
    expect(evaluatePin([pin()], facts, "issue:read", T2, 5000)).toBeNull();
  });

  test("target not matching key -> pin-inert", () => {
    const facts: PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];
    expect(evaluatePin([pin()], facts, "issue:write", "/user/orgs", 5000)).toBeNull();
  });

  test("expired fact (outside window) -> unit no longer pinned -> first-touch-free again", () => {
    const facts: PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];
    // now far past the window; the only fact is expired -> pinned set empty
    expect(evaluatePin([pin({ withinMs: 100 })], facts, "issue:write", T2, 5000)).toBeNull();
  });

  test("deny beats require_approval across rules", () => {
    const approvePin = pin();
    const denyPin = pin({ effect: "deny" });
    const facts: PinFact[] = [
      { ruleIndex: 0, unit: "acme/api", ts: 1000 },
      { ruleIndex: 1, unit: "acme/api", ts: 1000 },
    ];
    const hit = evaluatePin([approvePin, denyPin], facts, "issue:write", T2, 5000);
    expect(hit?.effect).toBe("deny");
  });

  test("maxWithinMs returns the largest window", () => {
    expect(maxWithinMs([pin({ withinMs: 1000 }), pin({ withinMs: 9000 })])).toBe(9000);
  });
});

describe("pinUnitsFor", () => {
  const CASES: readonly {
    name: string;
    action: string;
    target: string;
    expected: readonly { ruleIndex: number; unit: string }[];
  }[] = [
    { name: "matching action + key -> the unit", action: "issue:write", target: T, expected: [{ ruleIndex: 0, unit: "acme/api" }] },
    { name: "action outside `on` -> nothing", action: "issue:read", target: T, expected: [] },
    { name: "target the key cannot parse -> nothing", action: "issue:write", target: "/orgs/acme", expected: [] },
  ];
  for (const c of CASES) {
    test(c.name, () => {
      expect(pinUnitsFor([pin()], c.action, c.target)).toEqual(c.expected);
    });
  }

  test("reports one unit per matching rule", () => {
    const second = pin({ key: /^\/repos\/([^/]+)/ }); // unit = owner only
    expect(pinUnitsFor([pin(), second], "issue:write", T)).toEqual([
      { ruleIndex: 0, unit: "acme/api" },
      { ruleIndex: 1, unit: "acme" },
    ]);
  });

  test("pure: repeated calls agree (the key regex is not stateful)", () => {
    const a = pinUnitsFor([pin()], "issue:write", T);
    expect(pinUnitsFor([pin()], "issue:write", T)).toEqual([...a]);
  });
});

describe("evaluatePinBatch", () => {
  const pinned: readonly PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];

  test("all pairs on the pinned unit -> no hit", () => {
    const pairs = [
      { action: "issue:write", target: T },
      { action: "issue:write", target: T },
    ];
    expect(evaluatePinBatch([pin()], pinned, pairs, 5000)).toBeNull();
  });

  test("a pivot hidden in a later pair still hits", () => {
    const pairs = [
      { action: "issue:write", target: T },
      { action: "issue:write", target: T2 },
    ];
    expect(evaluatePinBatch([pin()], pinned, pairs, 5000)).toMatchObject({ unit: "acme/payroll" });
  });

  test("a fresh session pivoting WITHIN one batch hits (the intra-batch fold)", () => {
    // No stored facts: pair 1 establishes acme/api, pair 2 pivots off it. Two
    // sequential requests would escalate, so one batch must too.
    const pairs = [
      { action: "issue:write", target: T },
      { action: "issue:write", target: T2 },
    ];
    expect(evaluatePinBatch([pin()], [], pairs, 5000)).toMatchObject({ unit: "acme/payroll" });
  });

  test("a fresh session staying on one unit is free", () => {
    const pairs = [
      { action: "issue:write", target: T },
      { action: "issue:write", target: T },
    ];
    expect(evaluatePinBatch([pin()], [], pairs, 5000)).toBeNull();
  });

  test("strongest effect wins across pairs (deny beats require_approval)", () => {
    const denyRule = pin({ effect: "deny" });
    const pairs = [
      { action: "issue:write", target: T2 }, // hits rule 0 (require_approval)
      { action: "issue:write", target: T2 }, // hits rule 1 (deny)
    ];
    const hit = evaluatePinBatch([pin(), denyRule], pinned.concat({ ruleIndex: 1, unit: "acme/api", ts: 1000 }), pairs, 5000);
    expect(hit!.effect).toBe("deny");
  });

  test("a single pair matches plain evaluatePin exactly", () => {
    const one = [{ action: "issue:write", target: T2 }];
    expect(evaluatePinBatch([pin()], pinned, one, 5000)).toEqual(
      evaluatePin([pin()], pinned, "issue:write", T2, 5000),
    );
  });

  test("pure: does not mutate the caller's fact array", () => {
    const facts: PinFact[] = [{ ruleIndex: 0, unit: "acme/api", ts: 1000 }];
    evaluatePinBatch([pin()], facts, [{ action: "issue:write", target: T2 }], 5000);
    expect(facts).toHaveLength(1);
  });
});
