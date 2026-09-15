/**
 * Upstream adapters map a concrete wire request (HTTP method + path, or a
 * JSON-RPC body) onto one or more normalized `action` strings that the policy
 * engine understands (e.g. `pr:merge`, `call:create_issue`).
 *
 * Adapters are the beginning of Grenz's "policy graph": the shared knowledge
 * of which wire calls correspond to which risk-bearing actions. They are pure
 * functions of the request — no IO, no credentials.
 */

export interface AdapterRequest {
  /** Uppercase HTTP method. */
  readonly method: string;
  /** Path after the `/u/<upstream>` prefix, always starting with `/`. */
  readonly path: string;
  /** Raw query string without the leading `?` (may be empty). */
  readonly query: string;
  /** Raw request body bytes (may be empty). */
  readonly body: Uint8Array;
  /** Lowercased content-type, if present. */
  readonly contentType: string | null;
}

export interface AdapterMapping {
  /**
   * One normalized action per logical sub-request. Usually length 1; MCP
   * batches can produce several. Every action must be permitted for the whole
   * request to be allowed.
   */
  readonly actions: readonly string[];
  /**
   * The target each action acts on — `targets[i]` belongs to `actions[i]`, so
   * this array ALWAYS has the same length as `actions`.
   *
   * Every target-scoped gate (deny, require_approval, tripwire, response cap,
   * pin, agent/delegation scope) matches against these, never against
   * `target`. That is the whole point: a batch that collapsed its members into
   * one display label would launder a scoped rule, because no glob matches the
   * synthetic label. Keep the pairing exact.
   */
  readonly targets: readonly string[];
  /**
   * A log-safe DISPLAY label for the request as a whole (path, or method +
   * tool name; `batch(N)` for a multi-message MCP batch). Log and UI only —
   * never a matching input. Use `targets` to decide anything.
   */
  readonly target: string;
  /** A log-safe label for the protocol operation (HTTP verb or JSON-RPC method). */
  readonly label: string;
}

export interface AdapterUnsupported {
  readonly unsupported: string;
}

export type AdapterOutcome = AdapterMapping | AdapterUnsupported;

export function isUnsupported(o: AdapterOutcome): o is AdapterUnsupported {
  return "unsupported" in o;
}

export interface UpstreamAdapter {
  readonly type: string;
  map(req: AdapterRequest): AdapterOutcome;
}
