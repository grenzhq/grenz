/**
 * `bun build --compile` embeds a `with { type: "file" }` import and hands back a
 * path string that resolves inside the binary. TypeScript has no built-in
 * declaration for it.
 */
declare module "*.wasm" {
  const path: string;
  export default path;
}
