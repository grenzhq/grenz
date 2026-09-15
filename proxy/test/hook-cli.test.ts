import { test, expect, describe } from "bun:test";
import {
  commandFrom,
  block,
  proceed,
  hookTimeoutMs,
  describeAskFailure,
  CLAUDE_CODE_HOOK_TIMEOUT_MS,
} from "../src/cli/hook.ts";

/** The JSON a blocking hook writes to stdout. */
function decisionOf(stdout: string | null): Record<string, unknown> {
  expect(stdout).not.toBeNull();
  return JSON.parse(stdout!) as Record<string, unknown>;
}

describe("hook — the two denial paths (Claude Code #18312)", () => {
  test("a deny carries BOTH the JSON decision and exit code 2", () => {
    const out = block("nope");
    // Exit 2 is the load-bearing half: when the tool is already on the user's
    // allow-list, `permissionDecision` is ignored, and only the exit code still
    // blocks. Relying on the JSON alone would fail open for exactly the users
    // who allow-listed Bash.
    expect(out.code).toBe(2);

    const json = decisionOf(out.stdout);
    const specific = json["hookSpecificOutput"] as Record<string, unknown>;
    expect(specific["hookEventName"]).toBe("PreToolUse");
    expect(specific["permissionDecision"]).toBe("deny");
  });

  test("the reason reaches the model on both spellings and on stderr", () => {
    const out = block("Grenz denied this command (explicit_deny)");
    const json = decisionOf(out.stdout);
    const specific = json["hookSpecificOutput"] as Record<string, unknown>;
    expect(specific["permissionDecisionReason"]).toBe("Grenz denied this command (explicit_deny)");
    expect(json["systemMessage"]).toBe("Grenz denied this command (explicit_deny)");
    // On exit 2, stderr is what Claude Code feeds back to the model.
    expect(out.stderr).toBe("Grenz denied this command (explicit_deny)");
  });

  test("an allow is silent — it never emits permissionDecision", () => {
    // A Grenz allow is the absence of an objection, not an instruction to run.
    // Emitting `"allow"` would BYPASS the user's own allow-list and prompts,
    // making Grenz a way to WIDEN permissions. Grenz only narrows.
    const out = proceed();
    expect(out.code).toBe(0);
    expect(out.stdout).toBeNull();
    expect(out.stderr).toBeNull();
  });
});

describe("hook — payload extraction fails closed", () => {
  test("a Bash call yields its command", () => {
    const r = commandFrom({ tool_name: "Bash", tool_input: { command: "git status" } });
    expect(r).toEqual({ command: "git status" });
  });

  test("a different tool is skipped, not blocked", () => {
    const r = commandFrom({ tool_name: "Read", tool_input: { file_path: "/x" } });
    expect(r).toEqual({ skip: true });
  });

  test("a MISSING tool_name blocks — it is not treated as 'some other tool'", () => {
    // The absent case and the different-tool case are not the same. A renamed
    // field or a truncated payload must not wave a Bash call through.
    for (const payload of [{}, { tool_name: null }, { tool_name: "" }, { toolName: "Bash" }]) {
      const r = commandFrom(payload as never);
      expect("error" in r).toBe(true);
    }
  });

  test("a Bash call with no readable command blocks", () => {
    for (const payload of [
      { tool_name: "Bash" },
      { tool_name: "Bash", tool_input: null },
      { tool_name: "Bash", tool_input: {} },
      { tool_name: "Bash", tool_input: { command: "" } },
      { tool_name: "Bash", tool_input: { command: 42 } },
    ]) {
      const r = commandFrom(payload as never);
      expect("error" in r).toBe(true);
    }
  });
});

describe("hook — always answers before Claude Code's own timeout", () => {
  // A hook still running when Claude Code's per-hook timeout fires does NOT
  // block the call: the tool proceeds. So a wait that outlives it is a
  // fail-open, whatever the approval TTL says.
  test("the wait tracks the approval TTL", () => {
    expect(hookTimeoutMs(300)).toBe(310_000);
  });
  test("but is capped below Claude Code's default, for any TTL", () => {
    for (const ttl of [600, 900, 3600, 86_400]) {
      expect(hookTimeoutMs(ttl)).toBeLessThan(CLAUDE_CODE_HOOK_TIMEOUT_MS);
    }
  });
});

describe("hook — a failed ask says which failure it was", () => {
  // Found live: an approval sat unanswered and the message said "start the
  // proxy", which was already running.
  test("a timeout points at the approval, not the proxy", () => {
    const err = Object.assign(new Error("timed out"), { name: "TimeoutError" });
    const msg = describeAskFailure(err, 310_000);
    expect(msg).toContain("310s");
    expect(msg).toContain("grenz approvals");
    expect(msg).not.toContain("grenz run");
  });

  test("nothing listening points at the proxy", () => {
    for (const code of ["ConnectionRefused", "ECONNREFUSED", "FailedToOpenSocket", "ENOENT"]) {
      const msg = describeAskFailure(Object.assign(new Error("x"), { code }), 310_000);
      expect([code, msg.includes("grenz run")]).toEqual([code, true]);
    }
  });

  test("a dropped connection names both likely causes and the code", () => {
    const msg = describeAskFailure(Object.assign(new Error("x"), { code: "ECONNRESET" }), 310_000);
    expect(msg).toContain("ECONNRESET");
    expect(msg).toContain("grenz approvals");
  });

  test("a non-Error throw still produces a message", () => {
    expect(describeAskFailure(undefined, 310_000)).toContain("closed before it answered");
  });
});
