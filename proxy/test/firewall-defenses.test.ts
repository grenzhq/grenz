import { test, expect, describe } from "bun:test";
import type { ReasonCode } from "../src/policy/types.ts";
import { classifyDefense, DEFENSE_INFO, DEFENSE_CODES } from "../src/firewall/defenses.ts";

/**
 * The full ReasonCode union, written out as a literal. TypeScript checks this
 * array is exhaustive: if a ReasonCode is added or removed, `ALL_CODES` stops
 * being assignable to `ReasonCode[]` OR the completeness test below fails
 * because a member is neither classified nor excluded. Either way a new code
 * cannot silently fall through the firewall taxonomy.
 */
const ALL_CODES = [
  "explicit_allow",
  "explicit_deny",
  "approval_required",
  "no_matching_allow",
  "no_grant_for_tool",
  "budget_exceeded",
  "upstream_budget_exceeded",
  "agent_budget_exceeded",
  "delegation_budget_exceeded",
  "unknown_upstream",
  "invalid_token",
  "agent_token_expired",
  "malformed_policy",
  "credential_missing",
  "vault_error",
  "unsupported_request",
  "approvals_unavailable",
  "token_revoked",
  "revocation_stale",
  "response_too_large",
  "delegation_scope",
  "delegation_target_scope",
  "agent_target_scope",
  "agent_action_scope",
  "schedule_closed",
  "first_use_denied",
  "flow_denied",
  "tripwire",
  "decoy_token",
  "decoy_upstream",
  "wrong_listener",
  "pin_violation",
  "egress_blocked",
  "jit_grant",
  "approval_granted",
  "approval_denied",
  "approval_expired",
  "approval_capacity",
  "approval_abandoned",
  "approval_remembered_grant",
  "approval_remembered_deny",
  "dlp_secret_detected",
  "upstream_error",
  "internal_error",
] as const satisfies readonly ReasonCode[];

/** Codes that are deliberately NOT firewall-defense events. */
const EXCLUDED = new Set<string>([
  "explicit_allow",
  "approval_required",
  "approval_granted",
  "approval_denied",
  "approval_expired",
  "approval_abandoned",
  "approval_remembered_grant",
  "approval_remembered_deny",
  "approval_capacity",
  "jit_grant",
  "invalid_token", // wire-mask for decoy_token / agent_token_expired; true code is logged
  "malformed_policy",
  "credential_missing",
  "vault_error",
  "unsupported_request",
  "approvals_unavailable",
  "upstream_error",
  "internal_error",
]);

describe("classifyDefense — completeness", () => {
  test("every ReasonCode is either classified or explicitly excluded", () => {
    for (const code of ALL_CODES) {
      const classified = code in DEFENSE_INFO;
      const excluded = EXCLUDED.has(code);
      // Exactly one must hold — never both, never neither.
      expect(
        classified !== excluded,
        `${code}: classified=${classified} excluded=${excluded} (must be exactly one)`,
      ).toBe(true);
    }
  });

  test("classify returns null for every excluded code", () => {
    for (const code of EXCLUDED) {
      expect(classifyDefense(code)).toBeNull();
    }
  });

  test("classify returns a well-formed descriptor for every defense code", () => {
    for (const code of DEFENSE_CODES) {
      const d = classifyDefense(code);
      expect(d).not.toBeNull();
      expect(d!.code).toBe(code);
      expect(d!.label.length).toBeGreaterThan(0);
      expect(d!.blurb.length).toBeGreaterThan(0);
      expect(["trap", "trifecta", "identity", "exfil", "gate", "rate", "policy"]).toContain(d!.kind);
      expect(["high", "elevated", "base"]).toContain(d!.severity);
    }
  });

  test("DEFENSE_CODES matches the map keys exactly", () => {
    expect(new Set(DEFENSE_CODES)).toEqual(new Set(Object.keys(DEFENSE_INFO)));
  });
});

describe("classifyDefense — spot checks", () => {
  test("tripwire is a high-severity trap", () => {
    const d = classifyDefense("tripwire")!;
    expect(d.kind).toBe("trap");
    expect(d.severity).toBe("high");
    expect(d.label).toBe("Tripwire");
  });

  test("the lethal-trifecta gates are the trifecta kind", () => {
    expect(classifyDefense("flow_denied")!.kind).toBe("trifecta");
    expect(classifyDefense("pin_violation")!.kind).toBe("trifecta");
  });

  test("unknown_upstream is deny-by-default (policy), not excluded", () => {
    const d = classifyDefense("unknown_upstream");
    expect(d).not.toBeNull();
    expect(d!.kind).toBe("policy");
  });

  test("a bare invalid_token is not a defense (it is the wire mask)", () => {
    expect(classifyDefense("invalid_token")).toBeNull();
  });

  test("an unknown string is not a defense", () => {
    expect(classifyDefense("not_a_real_code")).toBeNull();
  });

  test("no defense blurb uses audit/compliance framing (bright line)", () => {
    const forbidden = /\b(audit|compliance|tamper|forensic|evidence|attest)/i;
    for (const code of DEFENSE_CODES) {
      const { label, blurb } = classifyDefense(code)!;
      expect(forbidden.test(blurb), `${code} blurb: ${blurb}`).toBe(false);
      expect(forbidden.test(label), `${code} label: ${label}`).toBe(false);
    }
  });
});
