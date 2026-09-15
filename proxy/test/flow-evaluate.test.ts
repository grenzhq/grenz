import { test, expect, describe } from "bun:test";
import { evaluateFlows, evaluateFlowsBatch, maxWithinMs } from "../src/flow/evaluate.ts";
import { compilePolicyYaml, type CompiledFlow } from "../src/policy/compile.ts";
import type { FlowFact } from "../src/flow/facts.ts";

function flows(yaml: string): readonly CompiledFlow[] {
  const r = compilePolicyYaml(`agent: a\non_behalf_of: x\n${yaml}`);
  if (!r.ok) throw new Error(r.error);
  return r.policy.flows;
}

const F = flows(`
flows:
  - when: ["*:read"]
    then: ["chat:write"]
    effect: require_approval
    within_seconds: 100
  - when: ["issue:read"]
    then: ["chat:write"]
    effect: deny
    within_seconds: 100
`);

const readFact = (ts: number): FlowFact => ({ action: "issue:read", target: "/r/1", ts });

describe("evaluateFlows", () => {
  test("source in window + sink -> gated (deny wins over approval)", () => {
    const hit = evaluateFlows(F, [readFact(1000)], "chat:write", 1050)!;
    expect(hit.effect).toBe("deny");
    expect(hit.source.action).toBe("issue:read");
  });

  test("source older than window -> null", () => {
    // fact at 1000, within_seconds=100 => 100_000ms; now past that => expired
    expect(evaluateFlows(F, [readFact(1000)], "chat:write", 1000 + 100_001)).toBeNull();
  });

  test("no source seen -> null", () => {
    expect(evaluateFlows(F, [], "chat:write", 5000)).toBeNull();
  });

  test("action is neither sink -> null", () => {
    expect(evaluateFlows(F, [readFact(1000)], "repo:read", 1050)).toBeNull();
  });

  test("only-approval flow when the deny flow's source doesn't match", () => {
    const hit = evaluateFlows(F, [{ action: "repo:read", target: null, ts: 1000 }], "chat:write", 1050)!;
    expect(hit.effect).toBe("require_approval"); // matched *:read, not issue:read
  });

  test("maxWithinMs returns the largest window", () => {
    expect(maxWithinMs(F)).toBe(100_000);
  });
});

describe("evaluateFlowsBatch", () => {
  test("no pair is a sink -> null", () => {
    const pairs = [{ action: "issue:read", target: "/r/1" }];
    expect(evaluateFlowsBatch(F, [], pairs, 5000)).toBeNull();
  });

  test("a sink hidden in a later pair still gates on a stored source", () => {
    const pairs = [
      { action: "issue:read", target: "/r/1" },
      { action: "chat:write", target: "/c/1" },
    ];
    const got = evaluateFlowsBatch(F, [readFact(1000)], pairs, 1050)!;
    expect(got.hit.effect).toBe("deny");
    expect(got.action).toBe("chat:write");
  });

  test("source AND sink inside ONE batch still gates (the intra-batch fold)", () => {
    // No stored facts at all: the batch carries both halves of read -> exfil.
    // Two sequential requests would be gated, so one batch must be too.
    const pairs = [
      { action: "issue:read", target: "/r/1" },
      { action: "chat:write", target: "/c/1" },
    ];
    const got = evaluateFlowsBatch(F, [], pairs, 5000)!;
    expect(got.hit.effect).toBe("deny");
    expect(got.hit.source.action).toBe("issue:read");
  });

  test("sink BEFORE the source in the same batch is not gated (order is honoured)", () => {
    const pairs = [
      { action: "chat:write", target: "/c/1" },
      { action: "issue:read", target: "/r/1" },
    ];
    expect(evaluateFlowsBatch(F, [], pairs, 5000)).toBeNull();
  });

  test("a single pair matches plain evaluateFlows exactly", () => {
    const one = [{ action: "chat:write", target: "/c/1" }];
    expect(evaluateFlowsBatch(F, [readFact(1000)], one, 1050)!.hit).toEqual(
      evaluateFlows(F, [readFact(1000)], "chat:write", 1050)!,
    );
  });

  test("pure: does not mutate the caller's fact array", () => {
    const facts: FlowFact[] = [readFact(1000)];
    evaluateFlowsBatch(F, facts, [{ action: "issue:read", target: "/r/2" }], 1050);
    expect(facts).toHaveLength(1);
  });
});
