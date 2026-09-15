/**
 * Pins the known tree-sitter-bash defect the bash adapter compensates for.
 *
 * The grammar can DROP a `simple_expansion` node while still reporting
 * `hasError === false`, so a word that really contains `$IFS` presents to a
 * consumer as a pure literal. That breaks the one invariant the whole guard
 * rests on — "any dynamic part means this word is not a literal" — which is why
 * `adapters/bash.ts` re-checks every folded literal against its raw source.
 *
 * Two jobs here:
 *   1. assert the compensating check actually catches it (the security property)
 *   2. assert the defect is still PRESENT (the maintenance signal)
 *
 * If (2) starts failing, the grammar fixed it. That is good news, not a bug:
 * confirm it, then update this test. Do not delete the check in bash.ts — it
 * covers the class, not this instance, and costs one string scan.
 *
 * Discovered by differential fuzzing against mvdan-sh over ~900k inputs; the
 * shape only appears at word lengths of four or more fragments, which is why a
 * shorter fuzz reported the parser as clean.
 */
import { test, expect, describe, beforeAll } from "bun:test";
import type { Parser } from "web-tree-sitter";
import { loadBashParser } from "../src/exec/parser.ts";
import { mapBashCommand, isUndecidable, type SyntaxNode } from "../src/adapters/bash.ts";

let parser: Parser;

beforeAll(async () => {
  parser = await loadBashParser();
});

const DYNAMIC_NODES = new Set([
  "expansion",
  "simple_expansion",
  "command_substitution",
  "process_substitution",
  "arithmetic_expansion",
  "ansi_c_string",
]);

/** How many dynamic nodes the GRAMMAR reports — not what the adapter concludes. */
function grammarDynamicCount(src: string): { count: number; hasError: boolean } {
  const tree = parser.parse(src)!;
  let count = 0;
  const walk = (n: any): void => {
    if (DYNAMIC_NODES.has(n.type)) count++;
    for (const c of n.namedChildren) if (c) walk(c);
  };
  walk(tree.rootNode);
  return { count, hasError: tree.rootNode.hasError };
}

function adapterRefuses(src: string): boolean {
  const tree = parser.parse(src);
  if (tree === null) return true;
  const out = mapBashCommand(tree.rootNode as unknown as SyntaxNode, src);
  return isUndecidable(out) || "unsupported" in out;
}

// Minimal reproductions found by the fuzz. Each really contains an expansion.
const DROPPED = ['a""$IFS-r', 'a""$IFS/x', 'a""$X.', 'echo a""$IFS-r'];

describe("tree-sitter-bash expansion-drop defect", () => {
  test("the defect is still present: grammar reports zero dynamic nodes, no error", () => {
    for (const src of DROPPED) {
      const { count, hasError } = grammarDynamicCount(src);
      expect(hasError).toBe(false);
      // If this becomes non-zero, the grammar was fixed. See the header.
      expect(count).toBe(0);
    }
  });

  test("the adapter refuses them anyway — the backstop, not the node set, decides", () => {
    for (const src of DROPPED) {
      expect(adapterRefuses(src)).toBe(true);
    }
  });

  test("the refusal is reported as a lossy parse, not a generic deny", () => {
    const src = 'a""$IFS-r';
    const tree = parser.parse(src)!;
    const out = mapBashCommand(tree.rootNode as unknown as SyntaxNode, src);
    expect(isUndecidable(out)).toBe(true);
    if (isUndecidable(out)) expect(out.undecidable).toBe("lossy_parse");
  });

  test("the second $IFS in a word is dropped when followed by a slash", () => {
    // The original discovery. One expansion survives here, so the binary rule
    // still denies — but the count is wrong, which is why the rule must never
    // be count-based or position-based.
    const { count, hasError } = grammarDynamicCount("rm$IFS-rf$IFS/tmp/x");
    expect(hasError).toBe(false);
    expect(count).toBe(1); // mvdan-sh, correctly, reports 2
  });

  test("the backstop does not fire on genuinely literal dollars", () => {
    // The check must be precise or it denies ordinary commands. Quoted and
    // escaped dollars are literal data and have to survive it.
    for (const src of ["echo '$5'", "echo \\$5", "echo '`not a command`'"]) {
      expect(adapterRefuses(src)).toBe(false);
    }
  });

  test("a $ that bash does not expand is literal, even inside double quotes", () => {
    // Found live: `grep -E "pass$|fail$"` was refused as a lossy parse. Bash
    // leaves a `$` alone unless a name, digit, brace, paren or special
    // parameter follows it.
    for (const src of [
      'grep -E "pass$|fail$" log.txt',
      'echo "cost: 5$"',
      'echo "a$ b"',
      'echo "it$\'s"',
      'echo "a$/b$.c$,d"',
    ]) {
      expect([src, adapterRefuses(src)]).toEqual([src, false]);
    }
  });

  test("and the target keeps that $ — it must never read narrower than the argument", () => {
    const src = 'grep -E "pass$|fail$" log.txt';
    const out = mapBashCommand(parser.parse(src)!.rootNode as unknown as SyntaxNode, src);
    if (isUndecidable(out) || "unsupported" in out) throw new Error("unexpectedly refused");
    expect(out.targets).toEqual(["grep -E pass$|fail$ log.txt"]);
  });

  test("a $ that bash WOULD expand still refuses when the parser hides it", () => {
    // The loosening must not reopen the defect: every DROPPED shape has a name
    // character after its `$`, or a `$` that ends a node where the follower is
    // out of view. Both still deny as lossy.
    for (const src of [...DROPPED, "echo 5$"]) {
      expect([src, adapterRefuses(src)]).toEqual([src, true]);
    }
  });
});
