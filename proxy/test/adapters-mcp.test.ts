import { test, expect, describe } from "bun:test";
import { mcpAdapter } from "../src/adapters/mcp.ts";
import { isUnsupported, type AdapterRequest } from "../src/adapters/types.ts";

function post(body: unknown): AdapterRequest {
  return {
    method: "POST",
    path: "/",
    query: "",
    body: new TextEncoder().encode(JSON.stringify(body)),
    contentType: "application/json",
  };
}

function actionsOf(r: AdapterRequest): string[] {
  const out = mcpAdapter.map(r);
  if (isUnsupported(out)) throw new Error(out.unsupported);
  return [...out.actions];
}

describe("mcp adapter", () => {
  test("tools/call -> call:<name>", () => {
    expect(actionsOf(post({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "create_issue" } }))).toEqual([
      "call:create_issue",
    ]);
  });

  test("tools/list -> tools:list", () => {
    expect(actionsOf(post({ jsonrpc: "2.0", id: 1, method: "tools/list" }))).toEqual(["tools:list"]);
  });

  test("resources/read -> resources:read", () => {
    expect(actionsOf(post({ jsonrpc: "2.0", id: 1, method: "resources/read" }))).toEqual(["resources:read"]);
  });

  test("initialize / ping -> session:*", () => {
    expect(actionsOf(post({ jsonrpc: "2.0", id: 1, method: "initialize" }))).toEqual(["session:initialize"]);
    expect(actionsOf(post({ jsonrpc: "2.0", id: 1, method: "ping" }))).toEqual(["session:ping"]);
  });

  test("notifications/* -> notify:*", () => {
    expect(actionsOf(post({ jsonrpc: "2.0", method: "notifications/initialized" }))).toEqual(["notify:initialized"]);
  });

  test("GET opens the event stream -> session:stream", () => {
    const out = mcpAdapter.map({ method: "GET", path: "/", query: "", body: new Uint8Array(0), contentType: null });
    if (isUnsupported(out)) throw new Error("unexpected");
    expect(out.actions).toEqual(["session:stream"]);
  });

  test("DELETE ends the session -> session:end", () => {
    const out = mcpAdapter.map({ method: "DELETE", path: "/", query: "", body: new Uint8Array(0), contentType: null });
    if (isUnsupported(out)) throw new Error("unexpected");
    expect(out.actions).toEqual(["session:end"]);
  });

  test("batch maps every message; all must be permitted", () => {
    const actions = actionsOf(
      post([
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "get_thing" } },
      ]),
    );
    expect(actions).toEqual(["tools:list", "call:get_thing"]);
  });

  test("tools/call missing name -> unsupported (fail closed)", () => {
    const out = mcpAdapter.map(post({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {} }));
    expect(isUnsupported(out)).toBe(true);
  });

  test("invalid JSON body -> unsupported", () => {
    const out = mcpAdapter.map({
      method: "POST",
      path: "/",
      query: "",
      body: new TextEncoder().encode("{not json"),
      contentType: "application/json",
    });
    expect(isUnsupported(out)).toBe(true);
  });

  test("message without method -> unsupported", () => {
    const out = mcpAdapter.map(post({ jsonrpc: "2.0", id: 1 }));
    expect(isUnsupported(out)).toBe(true);
  });
});

describe("mcp adapter: per-action targets", () => {
  function mapped(r: AdapterRequest) {
    const out = mcpAdapter.map(r);
    if (isUnsupported(out)) throw new Error(out.unsupported);
    return out;
  }

  test("single message: targets is [target]", () => {
    const out = mapped(post({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_x" } }));
    expect(out.targets).toEqual(["tools/call get_x"]);
    expect(out.target).toBe("tools/call get_x");
  });

  test("batch: one REAL target per message, never the display label", () => {
    const out = mapped(
      post([
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_prod" } },
      ]),
    );
    // Display label collapses (but still NAMES the members, so a human approving
    // it can see what it is); the matching inputs do not collapse at all.
    expect(out.target).toBe("batch(2): tools/list, tools/call delete_prod");
    expect(out.targets).toEqual(["tools/list", "tools/call delete_prod"]);
  });

  test("a long batch's display label is bounded (names 3, elides the rest)", () => {
    const out = mapped(
      post(
        Array.from({ length: 6 }, (_, i) => ({
          jsonrpc: "2.0",
          id: i + 1,
          method: "tools/call",
          params: { name: `t${i}` },
        })),
      ),
    );
    expect(out.target).toBe("batch(6): tools/call t0, tools/call t1, tools/call t2, +3 more");
    expect(out.targets).toHaveLength(6);
  });

  test("targets and actions are always the same length (the pairing invariant)", () => {
    for (const body of [
      { jsonrpc: "2.0", id: 1, method: "ping" },
      [{ jsonrpc: "2.0", id: 1, method: "ping" }],
      [
        { jsonrpc: "2.0", id: 1, method: "ping" },
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "a" } },
        { jsonrpc: "2.0", id: 3, method: "resources/read" },
      ],
    ]) {
      const out = mapped(post(body));
      expect(out.targets).toHaveLength(out.actions.length);
    }
  });

  test("GET and DELETE carry their own single target", () => {
    const get = mapped({ method: "GET", path: "/", query: "", body: new Uint8Array(0), contentType: null });
    expect(get.targets).toEqual(["GET stream"]);
    const del = mapped({ method: "DELETE", path: "/", query: "", body: new Uint8Array(0), contentType: null });
    expect(del.targets).toEqual(["DELETE session"]);
  });
});
