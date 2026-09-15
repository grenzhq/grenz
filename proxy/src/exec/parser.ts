/**
 * The bash parser: tree-sitter, loaded exactly once per process.
 *
 * This module exists so the wasm cost is paid at daemon startup, not per guarded
 * command. `grenz hook` never imports it — the hook is a thin socket client and
 * the parse happens inside the running proxy (see `cli/hook.ts`).
 *
 * Both `.wasm` files are EMBEDDED with `with { type: "file" }`. web-tree-sitter's
 * default loader resolves its runtime module relative to the script and dies
 * under `bun build --compile`:
 *
 *     ENOENT: no such file or directory, open '/$bunfs/root/web-tree-sitter.wasm'
 *
 * so the bytes are handed to `Parser.init` explicitly. Nothing here reads from
 * the filesystem at runtime.
 *
 * Provenance and hashes for both blobs: `vendor/wasm/PROVENANCE.md`.
 */
import { Parser, Language } from "web-tree-sitter";
import runtimeWasm from "../../vendor/wasm/web-tree-sitter.wasm" with { type: "file" };
import grammarWasm from "../../vendor/wasm/tree-sitter-bash.wasm" with { type: "file" };

let parser: Parser | null = null;
let loading: Promise<Parser> | null = null;

async function build(): Promise<Parser> {
  await Parser.init({
    wasmBinary: new Uint8Array(await Bun.file(runtimeWasm).arrayBuffer()),
  } as Parameters<typeof Parser.init>[0]);
  const language = await Language.load(new Uint8Array(await Bun.file(grammarWasm).arrayBuffer()));
  const p = new Parser();
  p.setLanguage(language);
  return p;
}

/**
 * Load the parser. Idempotent and concurrency-safe: overlapping callers during
 * startup share one load rather than racing two wasm instantiations.
 */
export function loadBashParser(): Promise<Parser> {
  if (parser !== null) return Promise.resolve(parser);
  loading ??= build().then(
    (p) => {
      parser = p;
      loading = null;
      return p;
    },
    (err) => {
      // Leave `loading` null so a later attempt can retry rather than latching a
      // rejected promise forever. A failure here means the guard cannot parse,
      // and every caller denies.
      loading = null;
      throw err;
    },
  );
  return loading;
}

/** True once the parser is resident, so callers can avoid an await on the hot path. */
export function bashParserReady(): boolean {
  return parser !== null;
}

/** The loaded parser, or null. For synchronous call sites that must not await. */
export function bashParserSync(): Parser | null {
  return parser;
}
