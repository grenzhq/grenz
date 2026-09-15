/**
 * Cap a response body at a byte count with a counting passthrough. Never holds
 * more than one chunk (O(1) memory) — SSE and large payloads still stream; the
 * stream is cut cleanly at the cap. Inspects NOTHING: it counts bytes and trims,
 * it never reads content. Pure — no I/O, no globals.
 */
export function capResponseBody(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): { stream: ReadableStream<Uint8Array> | null } {
  if (body === null) return { stream: null };
  let sent = 0;
  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (sent >= maxBytes) return; // already at the cap: drop the rest
      const remaining = maxBytes - sent;
      if (chunk.byteLength <= remaining) {
        controller.enqueue(chunk);
        sent += chunk.byteLength;
        // Cut AT the cap, not only past it: a chunk landing exactly on maxBytes
        // must still close the stream, or an aligned (e.g. SSE) upstream is
        // drained forever and its readable never EOFs to the agent.
        if (sent >= maxBytes) controller.terminate();
      } else {
        controller.enqueue(chunk.subarray(0, remaining));
        sent = maxBytes;
        controller.terminate(); // cut the stream cleanly at the cap
      }
    },
  });
  return { stream: body.pipeThrough(transform) };
}
