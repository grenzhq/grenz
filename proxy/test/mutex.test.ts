import { test, expect, describe } from "bun:test";
import { Mutex } from "../src/util/mutex.ts";

const tick = () => new Promise((r) => setTimeout(r, 1));

describe("Mutex", () => {
  test("serializes sections — no interleaving across awaits", async () => {
    const m = new Mutex();
    const order: string[] = [];
    const section = (name: string) =>
      m.run(async () => {
        order.push(`${name}:start`);
        await tick();
        order.push(`${name}:end`);
      });
    await Promise.all([section("a"), section("b"), section("c")]);
    expect(order).toEqual(["a:start", "a:end", "b:start", "b:end", "c:start", "c:end"]);
  });

  test("returns the section's resolved value", async () => {
    const m = new Mutex();
    expect(await m.run(async () => 42)).toBe(42);
  });

  test("a rejecting section does not wedge the queue", async () => {
    const m = new Mutex();
    const boom = m.run(async () => {
      throw new Error("boom");
    });
    await expect(boom).rejects.toThrow("boom");
    // The next section still runs.
    expect(await m.run(async () => "ok")).toBe("ok");
  });
});
