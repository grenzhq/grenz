import { test, expect, describe } from "bun:test";
import { configSchema } from "../src/config/schema.ts";

const base = {
  listen: { host: "127.0.0.1", port: 8787 },
  upstreams: {},
  agents: [{ id: "a", token_hash: "a".repeat(64) }],
};

// OIDC/IdP federation (`sso:`) is a Grenz Enterprise feature. The OSS build must
// FAIL CLOSED on an `sso:` block rather than boot as if federation were active —
// deny-by-default, with a structured reason pointing at the enterprise docs.
describe("sso: config is enterprise-only (fails closed in OSS)", () => {
  test("a config without sso parses (control)", () => {
    expect(() => configSchema.parse(base)).not.toThrow();
  });

  test("any sso: block is rejected with an enterprise pointer", () => {
    const cases: unknown[] = [
      { ...base, sso: {} },
      { ...base, sso: { issuer: "https://idp.example.com" } },
      { ...base, sso: true },
      { ...base, sso: { issuer: "https://idp.example.com", jwks_uri: "https://idp.example.com/keys", role_map: { admins: "admin" } } },
    ];
    for (const cfg of cases) {
      const res = configSchema.safeParse(cfg);
      expect(res.success).toBe(false);
      if (!res.success) {
        const msg = res.error.issues.map((i) => i.message).join(" | ");
        expect(msg).toContain("Grenz Enterprise");
        expect(msg).toContain("docs/enterprise.md");
      }
    }
  });
});
