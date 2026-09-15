import { test, expect, describe } from "bun:test";
import { scanForSecrets, scanBytes, findingLabel } from "../src/dlp/scan.ts";

describe("dlp scanner", () => {
  const positives: Array<[label: string, text: string, detector: string]> = [
    ["aws access key", "creds AKIAIOSFODNN7EXAMPLE here", "aws_access_key"],
    ["github token", `token ghp_${"a".repeat(36)} end`, "github_token"],
    ["slack token", "xoxb-1234567890-abcdefghijkl", "slack_token"],
    ["google api key", `AIza${"a".repeat(35)}`, "google_api_key"],
    ["stripe key", `sk_live_${"a".repeat(24)}`, "stripe_secret_key"],
    ["private key block", "-----BEGIN RSA PRIVATE KEY-----", "private_key"],
    ["secret assignment", 'password = "hunter2hunter2"', "generic_secret_assignment"],
  ];
  for (const [label, text, detector] of positives) {
    test(`detects ${label}`, () => {
      expect(scanForSecrets(text).map((f) => f.detector)).toContain(detector);
    });
  }

  test("no false positive on benign text", () => {
    expect(scanForSecrets("A normal PR description about refactoring the parser.")).toEqual([]);
  });

  test("a finding never contains the secret value — only name + count", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const findings = scanForSecrets(`before ${secret} after`);
    expect(JSON.stringify(findings)).not.toContain(secret);
    expect(findings[0]).toEqual({ detector: "aws_access_key", count: 1 });
  });

  test("counts multiple matches", () => {
    const findings = scanForSecrets(`ghp_${"a".repeat(36)} and ghp_${"b".repeat(40)}`);
    const gh = findings.find((f) => f.detector === "github_token");
    expect(gh?.count).toBe(2);
  });

  test("scanBytes decodes utf-8 bodies", () => {
    const findings = scanBytes(new TextEncoder().encode(`x sk_live_${"c".repeat(24)} y`));
    expect(findings.map((f) => f.detector)).toContain("stripe_secret_key");
  });

  test("findingLabel joins detector names only", () => {
    expect(findingLabel([{ detector: "aws_access_key", count: 1 }, { detector: "slack_token", count: 2 }])).toBe(
      "aws_access_key,slack_token",
    );
  });
});
