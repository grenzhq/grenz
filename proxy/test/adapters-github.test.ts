import { test, expect, describe } from "bun:test";
import { githubAdapter, GITHUB_ACTIONS } from "../src/adapters/github.ts";
import { isUnsupported, type AdapterRequest } from "../src/adapters/types.ts";

function req(method: string, path: string): AdapterRequest {
  return { method, path, query: "", body: new Uint8Array(0), contentType: null };
}

function actionOf(method: string, path: string): string {
  const out = githubAdapter.map(req(method, path));
  if (isUnsupported(out)) throw new Error(out.unsupported);
  expect(out.actions.length).toBe(1);
  return out.actions[0]!;
}

describe("github adapter", () => {
  const cases: Array<[method: string, path: string, action: string]> = [
    ["GET", "/repos/o/r", "repo:read"],
    ["GET", "/repos/o/r/contents/x", "repo:read"],
    ["DELETE", "/repos/o/r", "repo:delete"],
    ["POST", "/repos/o/r/pulls", "pr:create"],
    ["GET", "/repos/o/r/pulls", "pr:read"],
    ["GET", "/repos/o/r/pulls/5", "pr:read"],
    ["PATCH", "/repos/o/r/pulls/5", "pr:update"],
    ["PUT", "/repos/o/r/pulls/5/merge", "pr:merge"],
    ["POST", "/repos/o/r/issues/5/comments", "pr:comment"],
    ["POST", "/repos/o/r/pulls/5/comments", "pr:comment"],
    ["POST", "/repos/o/r/issues", "issue:create"],
    ["GET", "/repos/o/r/issues", "issue:read"],
    ["GET", "/repos/o/r/issues/5", "issue:read"],
    ["PATCH", "/repos/o/r/issues/5", "issue:update"],
    ["GET", "/repos/o/r/actions/runs", "actions:read"],
    ["POST", "/repos/o/r/actions/workflows/1/dispatches", "actions:write"],
    ["DELETE", "/repos/o/r/actions/runs/9", "actions:write"],
    ["PUT", "/repos/o/r/contents/file.txt", "repo:write"],
    ["GET", "/user", "user:read"],
    ["GET", "/user/repos", "user:read"],
    ["GET", "/orgs/acme", "org:read"],
    ["GET", "/search/code", "search:read"],
    // fallbacks
    ["GET", "/unmapped/endpoint", "api:read"],
    ["POST", "/unmapped/endpoint", "api:write"],
    ["POST", "/repos/o/r/merges", "repo:write"],
  ];

  for (const [method, path, action] of cases) {
    test(`${method} ${path} => ${action}`, () => {
      expect(actionOf(method, path)).toBe(action);
    });
  }

  test("unsupported HTTP method is rejected (fail closed)", () => {
    const out = githubAdapter.map(req("TRACE", "/repos/o/r"));
    expect(isUnsupported(out)).toBe(true);
  });

  test("mapping carries a log-safe target + label", () => {
    const out = githubAdapter.map(req("GET", "/repos/o/r"));
    if (isUnsupported(out)) throw new Error("unexpected");
    expect(out.target).toBe("/repos/o/r");
    expect(out.label).toBe("GET");
  });
});

describe("github action vocabulary", () => {
  test("contains every canonical action the rule table can produce", () => {
    expect(GITHUB_ACTIONS).toEqual(expect.arrayContaining([
      "repo:delete", "repo:read", "repo:write",
      "pr:merge", "pr:create", "pr:update", "pr:comment", "pr:read",
      "issue:create", "issue:update", "issue:read",
      "actions:read", "actions:write",
      "user:read", "org:read", "search:read",
      "api:read", "api:write",
    ]));
  });

  test("has no duplicates", () => {
    expect(new Set(GITHUB_ACTIONS).size).toBe(GITHUB_ACTIONS.length);
  });
});

/**
 * The precise rules are `$`-anchored; the coarse fallbacks are not. So a
 * spelling the anchored rule misses lands on a fallback with a cheaper name —
 * and a policy that explicitly denies `repo:delete` never sees a repo:delete.
 */
describe("github: slash spellings cannot buy an action a cheaper name", () => {
  function act(method: string, path: string): string {
    const out = githubAdapter.map(req(method, path));
    if (isUnsupported(out)) throw new Error(out.unsupported);
    return out.actions[0]!;
  }

  test("a trailing slash is still repo:delete", () => {
    expect(act("DELETE", "/repos/acme/api")).toBe("repo:delete");
    expect(act("DELETE", "/repos/acme/api/")).toBe("repo:delete");
    expect(act("DELETE", "/repos/acme/api///")).toBe("repo:delete");
  });

  test("a trailing slash is still pr:merge", () => {
    expect(act("PUT", "/repos/acme/api/pulls/7/merge")).toBe("pr:merge");
    expect(act("PUT", "/repos/acme/api/pulls/7/merge/")).toBe("pr:merge");
  });

  test("doubled slashes do not hide an action", () => {
    expect(act("DELETE", "/repos//acme//api")).toBe("repo:delete");
    expect(act("PUT", "/repos/acme/api//pulls//7//merge")).toBe("pr:merge");
  });

  test("normalizing does not invent a repo route out of a bare slash", () => {
    expect(act("GET", "/")).toBe("api:read");
    expect(act("POST", "/")).toBe("api:write");
    expect(act("POST", "///")).toBe("api:write");
  });

  test("ordinary paths are unchanged", () => {
    expect(act("GET", "/repos/acme/api/pulls/7")).toBe("pr:read");
    expect(act("POST", "/repos/acme/api/issues")).toBe("issue:create");
    expect(act("GET", "/user")).toBe("user:read");
  });
});
