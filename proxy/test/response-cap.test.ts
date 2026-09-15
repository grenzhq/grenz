import { test, expect, describe } from "bun:test";
import { capResponseBody } from "../src/response/cap.ts";

/** A ReadableStream that emits the given chunks (each a Uint8Array). */
function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(c);
      controller.close();
    },
  });
}

async function collect(stream: ReadableStream<Uint8Array> | null): Promise<Uint8Array> {
  if (stream === null) return new Uint8Array();
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    total += value.byteLength;
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}

function bytes(n: number, fill = 65): Uint8Array {
  return new Uint8Array(n).fill(fill);
}

describe("capResponseBody", () => {
  test("null body -> null stream", () => {
    expect(capResponseBody(null, 10).stream).toBeNull();
  });

  test("body under the cap passes through byte-identical", async () => {
    const { stream } = capResponseBody(streamOf([bytes(5)]), 10);
    expect((await collect(stream)).byteLength).toBe(5);
  });

  test("body exactly at the cap passes whole (== boundary, no off-by-one)", async () => {
    const { stream } = capResponseBody(streamOf([bytes(10)]), 10);
    expect((await collect(stream)).byteLength).toBe(10);
  });

  test("body over the cap is cut to exactly max_bytes", async () => {
    const { stream } = capResponseBody(streamOf([bytes(100)]), 10);
    expect((await collect(stream)).byteLength).toBe(10);
  });

  test("cut happens mid-chunk across many chunks (SSE shape)", async () => {
    const chunks = Array.from({ length: 20 }, () => bytes(8)); // 160 bytes in 8-byte chunks
    const { stream } = capResponseBody(streamOf(chunks), 25);
    expect((await collect(stream)).byteLength).toBe(25);
  });

  test("many small chunks under the cap all pass", async () => {
    const chunks = Array.from({ length: 4 }, () => bytes(3)); // 12 bytes
    const { stream } = capResponseBody(streamOf(chunks), 100);
    expect((await collect(stream)).byteLength).toBe(12);
  });

  test("a chunk landing EXACTLY on the cap with trailing chunks closes the stream (no drain)", async () => {
    // 100 chunks of 5 bytes, cap 25: chunk #5 lands exactly at 25. The stream
    // must close after it — the transform must NOT keep pulling the other 95.
    let pulled = 0;
    const src = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulled >= 100) {
          controller.close();
          return;
        }
        pulled++;
        controller.enqueue(bytes(5));
      },
    });
    const { stream } = capResponseBody(src, 25);
    expect((await collect(stream)).byteLength).toBe(25);
    // Only enough chunks to reach the cap should have been pulled (5), not all 100.
    expect(pulled).toBeLessThan(10);
  });
});
