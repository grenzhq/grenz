import { test, expect, describe } from "bun:test";
import { expiryStatus } from "../src/config/expiry.ts";

const DAY = 86_400_000;
const NOW = 100 * DAY;

describe("expiryStatus", () => {
  test("null → none", () => {
    expect(expiryStatus(null, NOW)).toBe("none");
  });
  test("boundary: expiresAtMs === now → expired", () => {
    expect(expiryStatus(NOW, NOW)).toBe("expired");
  });
  test("past → expired", () => {
    expect(expiryStatus(NOW - DAY, NOW)).toBe("expired");
  });
  test("within 7 days → soon", () => {
    expect(expiryStatus(NOW + 6 * DAY, NOW)).toBe("soon");
  });
  test("exactly 7 days out → soon (boundary is inclusive)", () => {
    expect(expiryStatus(NOW + 7 * DAY, NOW)).toBe("soon");
  });
  test("far future → ok", () => {
    expect(expiryStatus(NOW + 30 * DAY, NOW)).toBe("ok");
  });
  test("custom soonMs window is honored", () => {
    expect(expiryStatus(NOW + 2 * DAY, NOW, DAY)).toBe("ok");
    expect(expiryStatus(NOW + DAY, NOW, DAY)).toBe("soon");
  });
});
