import { test, expect, describe } from "bun:test";
import { runDemoCascade } from "../src/cli/demo-cascade.ts";
import { parseArgs } from "../src/cli/args.ts";

describe("grenz demo-cascade", () => {
  test("shows one tripped decoy killing the whole tree, no creds printed", async () => {
    const out: string[] = [];
    const orig = process.stdout.write;
    process.stdout.write = ((s: string | Uint8Array) => {
      out.push(String(s));
      return true;
    }) as typeof process.stdout.write;

    let code: number;
    try {
      code = await runDemoCascade(parseArgs([]));
    } finally {
      process.stdout.write = orig;
    }

    const text = out.join("");
    expect(code).toBe(0);
    // The swarm works first: at least the three initial reads are allowed.
    expect((text.match(/allow/g) ?? []).length).toBeGreaterThanOrEqual(3);
    // The raided sub-agent's honeytoken touch is a masked trap.
    expect(text).toContain("no_matching_allow");
    // After one trip, EVERY member of the tree is cut off — lead, reviewer, and
    // the raided runner all hit token_revoked (three cascade victims).
    expect((text.match(/token_revoked/g) ?? []).length).toBeGreaterThanOrEqual(3);
    // No real credential material is ever printed.
    expect(text).not.toContain("dummy-not-a-real-token");
  });
});
