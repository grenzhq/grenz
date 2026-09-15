import { test, expect, describe, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPolicy } from "../src/cli/policy.ts";
import { PolicyHistoryStore } from "../src/policy/history-store.ts";
import type { ParsedArgs } from "../src/cli/args.ts";

let home: string;

const POLICY_V1 = `agent: a\non_behalf_of: b\ngrants:\n  - tool: github\n    allow: [repo:read]\n`;
const POLICY_V2 = `agent: a\non_behalf_of: b\ngrants:\n  - tool: github\n    allow: [repo:read, pr:merge]\n`;

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "grenz-histcli-"));
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

function args(positionals: string[], flags: Record<string, string | boolean> = {}): ParsedArgs {
  const map = new Map<string, string | boolean>(Object.entries({ home, ...flags }));
  return { positionals, flags: map };
}

describe("grenz policy history / rollback", () => {
  test("history on an empty store exits 0", async () => {
    await writeFile(join(home, "policy.yaml"), POLICY_V1);
    const code = await runPolicy(args(["history"]));
    expect(code).toBe(0);
  });

  test("rollback dry-run writes nothing", async () => {
    await writeFile(join(home, "policy.yaml"), POLICY_V2);
    const store = new PolicyHistoryStore(join(home, "policy-history"));
    store.record(POLICY_V1, Date.UTC(2026, 0, 1)); // snapshot #1 = the old v1
    const code = await runPolicy(args(["rollback", "1"])); // no --yes
    expect(code).toBe(0);
    expect(readFileSync(join(home, "policy.yaml"), "utf8")).toBe(POLICY_V2); // unchanged
  });

  test("rollback --yes restores bytes and snapshots the prior file", async () => {
    await writeFile(join(home, "policy.yaml"), POLICY_V2);
    const histDir = join(home, "policy-history");
    const store = new PolicyHistoryStore(histDir);
    store.record(POLICY_V1, Date.UTC(2026, 0, 1)); // snapshot #1 = v1
    const code = await runPolicy(args(["rollback", "1"], { yes: true }));
    expect(code).toBe(0);
    expect(readFileSync(join(home, "policy.yaml"), "utf8")).toBe(POLICY_V1); // restored
    // the prior file (v2) was snapshotted before the overwrite -> 2 snapshots now
    expect(new PolicyHistoryStore(histDir).list().length).toBe(2);
  });

  test("rollback out-of-range exits 1, leaves policy.yaml alone", async () => {
    await writeFile(join(home, "policy.yaml"), POLICY_V2);
    await mkdir(join(home, "policy-history"), { recursive: true });
    const code = await runPolicy(args(["rollback", "9"]));
    expect(code).toBe(1);
    expect(readFileSync(join(home, "policy.yaml"), "utf8")).toBe(POLICY_V2);
  });

  test("rollback to a non-compiling snapshot is refused (exit 1)", async () => {
    await writeFile(join(home, "policy.yaml"), POLICY_V2);
    const store = new PolicyHistoryStore(join(home, "policy-history"));
    store.record("garbage: [not valid", Date.UTC(2026, 0, 1));
    const code = await runPolicy(args(["rollback", "1"], { yes: true }));
    expect(code).toBe(1);
    expect(readFileSync(join(home, "policy.yaml"), "utf8")).toBe(POLICY_V2); // untouched
  });
});
