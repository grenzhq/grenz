import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { SlackNotifier } from "../src/notify/slack.ts";

let posts: string[] = [];
let fake: ReturnType<typeof Bun.serve>;
let url: string;

beforeAll(() => {
  fake = Bun.serve({
    port: 0,
    async fetch(req) {
      const body = (await req.json()) as { text: string };
      posts.push(body.text);
      return new Response("ok");
    },
  });
  url = `http://127.0.0.1:${fake.port}`;
});
afterAll(() => fake.stop(true));

describe("SlackNotifier.decoyTripped", () => {
  test("token trip posts an alert naming the actor, never a token value", async () => {
    posts = [];
    const n = new SlackNotifier(url, () => {});
    await n.decoyTripped!("token", "trap-agent", "github", "/u/github/x");
    expect(posts).toHaveLength(1);
    expect(posts[0]).toContain("trap-agent");
    expect(posts[0]).toContain("revoked");
    expect(posts[0]!.toLowerCase()).toContain("decoy");
  });

  test("upstream trip names the upstream and path", async () => {
    posts = [];
    const n = new SlackNotifier(url, () => {});
    await n.decoyTripped!("upstream", "claude-1", "billing", "/u/billing/charge");
    expect(posts[0]).toContain("billing");
    expect(posts[0]).toContain("/u/billing/charge");
  });

  test("never throws when the webhook is unreachable", async () => {
    const n = new SlackNotifier("http://127.0.0.1:1", () => {});
    await n.decoyTripped!("token", "x", "y", "/z"); // must resolve, not reject
  });
});
