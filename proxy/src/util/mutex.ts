/**
 * A minimal async mutex: serializes critical sections that must not interleave
 * across awaits on a single-threaded event loop. `run(fn)` queues `fn` behind
 * every earlier call and resolves with its result. A rejection in one section
 * never wedges the queue — the chain always advances.
 *
 * Used to serialize grenz.yaml rewrites (a read → mint → write → rename cycle
 * that must be atomic against a concurrent console mint).
 */
export class Mutex {
  private tail: Promise<unknown> = Promise.resolve();

  run<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.tail.then(fn, fn);
    // The queue must advance whether fn resolves or rejects; swallow here so a
    // failed section doesn't poison the next one. Callers still see fn's outcome.
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
