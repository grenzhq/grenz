import { test, expect } from "bun:test";
import {
  applyCapability,
  readCapabilities,
  losesScope,
  type EditorGrant,
} from "./capabilities.ts";

/** A cut-down copy of the real bash policy's shape, including the parts that
 *  break a naive mapper: one `exec:git` allow rule whose targets belong to two
 *  different capabilities, a `cd` grant narrowed to specific folders, unscoped
 *  approval rules, and an unscoped deny. */
function realPolicy(): EditorGrant {
  return {
    tool: "bash",
    allow: [
      {
        action: "exec:git",
        targets: [
          "git status*",
          "git log*",
          "git add *",
          "git commit *",
          // Belongs to no capability: the prefix is `git -c`, not `git fetch`.
          "git -c credential.helper=* fetch *",
        ],
      },
      { action: "exec:bun", targets: ["bun test*", "bun run *"] },
      { action: "exec:head", targets: ["head *"] },
      { action: "exec:grep", targets: ["grep *"] },
      { action: "exec:cd", targets: ["cd proxy*", "cd ..", "cd /tmp/*"] },
      { action: "exec:grenz", targets: ["grenz *"] },
    ],
    require_approval: [
      { action: "exec:git", targets: ["git push*", "git reset*"] },
      "exec:curl",
      "exec:rm",
    ],
    deny: ["exec:sudo", "exec:ssh"],
  };
}

function row(grant: EditorGrant, id: string) {
  const found = readCapabilities(grant).rows.find((r) => r.cap.id === id);
  if (!found) throw new Error(`no such capability: ${id}`);
  return found;
}

test("one rule's targets can land in two different capabilities", () => {
  const g = realPolicy();
  expect(row(g, "git-local").state).toBe("allow");
  expect(row(g, "git-local").present).toBe(true);
  expect(row(g, "git-publish").state).toBe("ask");
});

test("a target no capability names survives as a leftover, not a silent drop", () => {
  const { leftovers } = readCapabilities(realPolicy());
  const flat = leftovers.flatMap((l) => l.targets);
  expect(flat).toContain("git -c credential.helper=* fetch *");
  // ...and the rest of that same rule is NOT duplicated into leftovers.
  expect(flat).not.toContain("git status*");
});

test("an unnamed binary becomes a leftover instead of being mislabelled", () => {
  const { leftovers } = readCapabilities(realPolicy());
  expect(leftovers.some((l) => l.action === "exec:grenz")).toBe(true);
});

test("many read binaries collapse into one row", () => {
  const r = row(realPolicy(), "read");
  expect(r.present).toBe(true);
  expect(r.state).toBe("allow");
  expect(r.commands).toEqual(["grep", "head"]);
});

test("a grant tighter than its name is reported as narrowed", () => {
  expect(row(realPolicy(), "navigate").narrowedTo).toBe(3);
  // `head *` only pins the basename, so it is not narrowing anything.
  expect(row(realPolicy(), "read").narrowedTo).toBe(0);
});

test("a capability with no rules reads as blocked, but not as written down", () => {
  const r = row(realPolicy(), "processes");
  expect(r.state).toBe("block");
  expect(r.present).toBe(false);
});

test("unscoped approval and deny rules are picked up", () => {
  expect(row(realPolicy(), "network").state).toBe("ask");
  expect(row(realPolicy(), "files").state).toBe("ask");
  expect(row(realPolicy(), "admin").state).toBe("block");
  expect(row(realPolicy(), "remote").state).toBe("block");
});

test("moving a capability keeps its targets exactly", () => {
  const next = applyCapability(realPolicy(), "navigate", "ask");
  const moved = next.require_approval.find(
    (e) => typeof e === "object" && (e as { action?: string }).action === "exec:cd",
  ) as { targets: string[] };
  expect(moved.targets).toEqual(["cd proxy*", "cd ..", "cd /tmp/*"]);
  expect(next.allow.some((e) => typeof e === "object" && (e as { action?: string }).action === "exec:cd")).toBe(false);
  expect(row(next, "navigate").state).toBe("ask");
  expect(row(next, "navigate").narrowedTo).toBe(3);
});

test("moving part of a binary leaves the rest of its rule alone", () => {
  const next = applyCapability(realPolicy(), "git-local", "ask");
  expect(row(next, "git-local").state).toBe("ask");
  // The unnameable target stayed in `allow`, on its original rule.
  const stillAllowed = next.allow.find(
    (e) => typeof e === "object" && (e as { action?: string }).action === "exec:git",
  ) as { targets: string[] };
  expect(stillAllowed.targets).toEqual(["git -c credential.helper=* fetch *"]);
});

test("blocking a whole binary writes an unscoped deny", () => {
  const next = applyCapability(realPolicy(), "network", "block");
  expect(next.deny).toContain("exec:curl");
  expect(next.require_approval).not.toContain("exec:curl");
});

test("blocking part of a binary removes the allow rather than writing an evadable deny", () => {
  const next = applyCapability(realPolicy(), "git-publish", "block");
  expect(row(next, "git-publish").state).toBe("block");
  expect(row(next, "git-publish").present).toBe(false);
  // No `git push*` deny rule was invented — argument order could step around it.
  expect(JSON.stringify(next.deny)).not.toContain("git push");
  // And blocking publishing did not disturb committing.
  expect(row(next, "git-local").state).toBe("allow");
});

test("switching on a capability that has no rules anchors both target forms", () => {
  const next = applyCapability(realPolicy(), "processes", "allow");
  const kill = next.allow.find(
    (e) => typeof e === "object" && (e as { action?: string }).action === "exec:kill",
  ) as { targets: string[] };
  // Both forms: a glob's space is literal, so `kill *` alone misses a bare
  // `kill` at the end of a pipeline.
  expect(kill.targets).toEqual(["kill", "kill *"]);
});

test("a capability whose rules span two clauses is flagged rather than tidied", () => {
  const g = realPolicy();
  g.require_approval.push({ action: "exec:head", targets: ["head /etc/*"] });
  expect(row(g, "read").mixed).toBe(true);
});

test("losing target scope to a block is reported", () => {
  expect(losesScope(row(realPolicy(), "navigate"), "block")).toBe(true);
  expect(losesScope(row(realPolicy(), "read"), "block")).toBe(false);
});

test("an empty policy reads as everything blocked and nothing written", () => {
  const { rows, leftovers } = readCapabilities(undefined);
  expect(leftovers).toHaveLength(0);
  expect(rows.every((r) => r.state === "block" && !r.present)).toBe(true);
});

test("a capability that claims part of a binary lists command shapes, not the binary", () => {
  // "1 command: git" would be useless under a row that means "commit, but do
  // not publish" — what it covers is the shapes.
  expect(row(realPolicy(), "git-local").commands).toEqual([
    "git add *",
    "git commit *",
    "git log*",
    "git status*",
  ]);
  expect(row(realPolicy(), "git-publish").commands).toEqual(["git push*", "git reset*"]);
});
