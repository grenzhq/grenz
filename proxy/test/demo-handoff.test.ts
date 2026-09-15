import { test, expect, describe } from "bun:test";
import { runDemoHandoff } from "../src/cli/demo-handoff.ts";
import { parseArgs } from "../src/cli/args.ts";

/**
 * The demo makes a security claim in front of an audience, so it gets a test:
 * a refactor that quietly turned either refusal into an allow would otherwise
 * leave a launch demo asserting something untrue on someone else's machine.
 */
describe("grenz demo-handoff", () => {
  test("the lead merges, the sub-agent four hops down cannot, no creds printed", async () => {
    const out: string[] = [];
    const orig = process.stdout.write;
    process.stdout.write = ((s: string | Uint8Array) => {
      out.push(String(s));
      return true;
    }) as typeof process.stdout.write;

    let code: number;
    try {
      code = await runDemoHandoff(parseArgs([]));
    } finally {
      process.stdout.write = orig;
    }

    const text = out.join("");
    expect(code).toBe(0);

    // The work itself flows: four reads/creates plus the lead's own merge.
    expect((text.match(/allow/g) ?? []).length).toBeGreaterThanOrEqual(5);

    // The whole point rests on the root really holding pr:merge — otherwise the
    // refusal below would just be "the policy forbids merging" and would prove
    // nothing about delegation.
    expect(text).toMatch(/lead\s+merge the PR\s+allow/);

    // Both refusals are the chain fold, not a policy deny: the committer's own
    // merge, and the merge attempted through a sub-token that CLAIMS pr:merge.
    expect((text.match(/delegation_scope/g) ?? []).length).toBe(2);
    expect(text).toMatch(/committer\s+merge the PR\s+deny\s+delegation_scope/);
    expect(text).toMatch(/its child\s+merge the PR\s+deny\s+delegation_scope/);

    // No real credential material is ever printed.
    expect(text).not.toContain("dummy-not-a-real-token");
  });
});
