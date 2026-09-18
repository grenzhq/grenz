import { test, expect } from "bun:test";
import { buildReview } from "./review.ts";
import type { RequestRow } from "./types.ts";

/** Real traffic, taken from the bash guard's own log. */
function log(): RequestRow[] {
  const base = {
    agentId: "claude-code",
    upstream: "bash",
    tool: "bash",
    method: "exec",
    reason: "explicit_allow",
    forwarded: false,
    status: null,
  };
  const rows: Array<[string, string, RequestRow["decision"], number]> = [
    ["exec:cat", "cat proxy/src/policy/engine.ts", "allow", 900],
    ["exec:grep", "grep -n Decision console/lib/types.ts", "allow", 880],
    ["exec:ls", "ls -la console/app", "allow", 870],
    ["exec:git", "git status", "allow", 860],
    ["exec:git", "git commit -m wip", "allow", 850],
    ["exec:git", "git push origin main", "require_approval", 840],
    ["exec:bun", "bun run build", "allow", 830],
    // The quiet one: allowed, harmless-looking, and a private key.
    ["exec:head", "head -50 ~/.ssh/id_ed25519", "allow", 820],
    ["exec:sudo", "sudo launchctl unload com.x", "deny", 810],
    ["exec:doas", "doas rm /etc/hosts", "deny", 805],
    ["exec:ssh", "ssh deploy@10.0.3.7", "deny", 800],
    ["exec:rm", "rm -rf proxy/dist", "require_approval", 790],
    ["exec:wobble", "wobble --frobnicate", "deny", 780],
  ];
  return rows.map(([action, target, decision, ts]) => ({ ...base, action, target, decision, ts }));
}

test("administrator access is the first thing you are asked about", () => {
  const r = buildReview(log());
  expect(r.flagged[0]?.cap.id).toBe("admin");
  expect(r.flagged[0]?.suggested).toBe("block");
});

test("reading a private key is flagged even though it was allowed", () => {
  const r = buildReview(log());
  const read = r.flagged.find((i) => i.cap.id === "read");
  expect(read).toBeDefined();
  expect(read!.flag).toBe("sensitive-path");
  // And it is proposed as Ask, never widened just because it succeeded.
  expect(read!.suggested).toBe("ask");
});

test("the flagged evidence leads with the sensitive target, not whatever came first", () => {
  const read = buildReview(log()).flagged.find((i) => i.cap.id === "read");
  expect(read!.examples[0]).toBe("head -50 ~/.ssh/id_ed25519");
});

test("routine work is proposed at its default and ordered by how often it happened", () => {
  const r = buildReview(log());
  const ids = r.routine.map((i) => i.cap.id);
  expect(ids).toContain("git-local");
  expect(ids).toContain("build");
  expect(r.routine.find((i) => i.cap.id === "git-local")!.suggested).toBe("allow");
  // Publishing is never proposed as allow, however routine it looks.
  expect(r.flagged.concat(r.routine).find((i) => i.cap.id === "git-publish")!.suggested).toBe("ask");
});

test("a command no capability names is counted, not silently dropped", () => {
  const r = buildReview(log());
  expect(r.unrecognized).toBe(1);
  expect(r.total).toBe(13);
});

test("an empty log proposes nothing at all", () => {
  const r = buildReview([]);
  expect(r.flagged).toHaveLength(0);
  expect(r.routine).toHaveLength(0);
  expect(r.total).toBe(0);
});
