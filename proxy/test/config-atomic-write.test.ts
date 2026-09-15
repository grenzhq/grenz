import { test, expect, describe, beforeEach } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeConfigAtomic, ConfigChangedError } from "../src/config/atomic-write.ts";

describe("writeConfigAtomic", () => {
  let path: string;
  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), "grenz-atomic-"));
    path = join(dir, "grenz.yaml");
  });

  test("writes new contents when the base matches", async () => {
    await writeFile(path, "base\n");
    writeConfigAtomic(path, "next\n", "base\n");
    expect(await readFile(path, "utf8")).toBe("next\n");
  });

  test("aborts and leaves the file untouched when it changed underfoot", async () => {
    await writeFile(path, "base\n");
    // Another process rewrote the file after we read `base` but before we rename.
    await writeFile(path, "someone-else\n");
    expect(() => writeConfigAtomic(path, "next\n", "base\n")).toThrow(ConfigChangedError);
    expect(await readFile(path, "utf8")).toBe("someone-else\n");
  });

  test("leaves no temp file behind on a conflict", async () => {
    const dir = await mkdtemp(join(tmpdir(), "grenz-atomic-"));
    const p = join(dir, "grenz.yaml");
    await writeFile(p, "base\n");
    await writeFile(p, "changed\n");
    expect(() => writeConfigAtomic(p, "next\n", "base\n")).toThrow(ConfigChangedError);
    const { readdirSync } = await import("node:fs");
    const leftovers = readdirSync(dir).filter((f) => f.includes(".tmp."));
    expect(leftovers).toEqual([]);
  });
});
