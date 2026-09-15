# Vendored WebAssembly — provenance

Grenz signs policy bundles with Ed25519. Shipping unverified binary blobs in the
same repo would be inconsistent with that posture, so every `.wasm` here is
pinned to a named upstream release and hash-checked in CI.

These files are vendored rather than installed because the npm package that
carries the bash grammar (`tree-sitter-bash`) declares `node-addon-api` +
`node-gyp-build` and runs a postinstall script to build native bindings Grenz
never uses. Vendoring the prebuilt `.wasm` takes the whole native-toolchain and
postinstall surface out of the dependency graph. Only `web-tree-sitter` (the
pure-JS loader, zero dependencies, no install script) is an actual dependency.

Both files are embedded into the compiled binary by `bun build --compile` via
`with { type: "file" }` imports in `proxy/src/exec/parser.ts`. Nothing is read
from disk at runtime.

## Files

### `web-tree-sitter.wasm`

| | |
|---|---|
| Package | `web-tree-sitter` |
| Version | `0.27.0` |
| Source | https://registry.npmjs.org/web-tree-sitter/-/web-tree-sitter-0.27.0.tgz |
| Path in tarball | `package/web-tree-sitter.wasm` |
| Upstream | https://github.com/tree-sitter/tree-sitter |
| License | MIT |
| SHA-256 (file) | `c03bccdc3b448a32848f5ae327e209c982bbb0840d43eec8bc2d5759544a1ed3` |
| SHA-256 (tarball) | `266e839d9d7f89c84ba6ce089ffdec9599b0a668c010308f857baad0570a0d50` |

The tree-sitter runtime. Must stay in lockstep with the `web-tree-sitter`
version in `proxy/package.json` — the JS loader and this module are one unit.

### `tree-sitter-bash.wasm`

| | |
|---|---|
| Package | `tree-sitter-bash` |
| Version | `0.25.1` |
| Source | https://registry.npmjs.org/tree-sitter-bash/-/tree-sitter-bash-0.25.1.tgz |
| Path in tarball | `package/tree-sitter-bash.wasm` |
| Upstream | https://github.com/tree-sitter/tree-sitter-bash |
| License | MIT |
| SHA-256 (file) | `8292919c88a0f7d3fb31d0cd0253ca5a9531bc1ede82b0537f2c63dd8abe6a7a` |
| SHA-256 (tarball) | `d4b2819508ea97cb8953fff7e304a610d443007bd395c8f03a15de9a8ae4a6f9` |

The bash grammar. `tree-sitter-bash` is NOT a dependency in `package.json` — only
this extracted file is used.

**Known grammar defect, compensated for in code.** This grammar can drop a
`simple_expansion` node while reporting `hasError === false`, so a word that
really contains `$IFS` can present as a pure literal. Minimal case:

```
a""$IFS-r   ->   command_name "a\"\"$"  +  word "IFS-r"     (zero expansion nodes)
```

`proxy/src/adapters/bash.ts` does not trust the node set alone. It applies two
parser-independent checks — a raw-string scan for `$`, a backtick, `<(`, `>(`,
and a span-coverage check that every byte of a word is accounted for by a node
the folder understands. Either one firing on a word the parser called literal is
a contradiction and denies. See `test/bash-parser-defect.test.ts`, which pins
the defect so a grammar bump that fixes it is noticed rather than silently
relied upon.

## Verifying

```sh
bun run verify:wasm
```

Run in CI on every push. It re-hashes each file against `checksums.txt` and
fails on any mismatch.

## Updating

Do not drop in a new `.wasm` by hand.

1. Pick the exact upstream version. Never a range.
2. Download the named tarball from the registry and record its SHA-256:
   ```sh
   curl -sL https://registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz -o pkg.tgz
   shasum -a 256 pkg.tgz
   ```
3. Extract only the `.wasm` and hash it:
   ```sh
   tar xzf pkg.tgz && shasum -a 256 package/<name>.wasm
   ```
4. Replace the file, update this document's version/URL/hashes, and regenerate
   the checksum file:
   ```sh
   bun run verify:wasm --write
   ```
5. Re-run the parser-defect test. If a grammar bump makes
   `test/bash-parser-defect.test.ts` fail, the defect is fixed upstream —
   confirm that, then update the test to assert the new behavior. Do NOT delete
   the compensating checks in `adapters/bash.ts`; they are cheap and cover the
   whole class, not this one instance.
6. If `web-tree-sitter.wasm` changed, bump `web-tree-sitter` in
   `proxy/package.json` to the same version in the same commit.
