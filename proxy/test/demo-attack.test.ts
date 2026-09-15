import { test, expect, describe } from "bun:test";
import { runDemoAttack } from "../src/cli/demo-attack.ts";
import { parseArgs } from "../src/cli/args.ts";

describe("grenz demo-attack", () => {
  test("answers 'just scope the token' — approval, no-credential, instant revoke", async () => {
    const out: string[] = [];
    const orig = process.stdout.write;
    process.stdout.write = ((s: string | Uint8Array) => {
      out.push(String(s));
      return true;
    }) as typeof process.stdout.write;

    let code: number;
    try {
      code = await runDemoAttack(parseArgs([]));
    } finally {
      process.stdout.write = orig;
    }

    const text = out.join("");
    expect(code).toBe(0);
    // the objection this demo exists to rebut
    expect(text).toContain("what a scoped token still can't do");
    // legit read flows
    expect(text).toContain("allow");
    // an in-scope action (pr:merge) is held for a human, who denies it — the
    // thing a bare scoped PAT would just do
    expect(text).toContain("approval_denied");
    // the operator revoke is the ONLY thing that cuts the agent off, so
    // token_revoked here proves the revoke — not an incidental tripwire
    expect(text).toContain("token_revoked");
    // no real credential material is ever printed
    expect(text).not.toContain("dummy-not-a-real-token");
  });
});
