import { test, expect, describe } from "bun:test";
import { hasRole, requiredRole } from "../src/admin/role.ts";

describe("hasRole", () => {
  test("rank ordering viewer<approver<admin", () => {
    expect(hasRole("admin", "approver")).toBe(true);
    expect(hasRole("approver", "viewer")).toBe(true);
    expect(hasRole("viewer", "approver")).toBe(false);
    expect(hasRole("approver", "admin")).toBe(false);
    expect(hasRole("viewer", "viewer")).toBe(true);
  });
});

describe("requiredRole (deny-by-default)", () => {
  test("GET read paths -> viewer", () => {
    expect(requiredRole("GET", "/console/summary")).toBe("viewer");
    expect(requiredRole("GET", "/console/requests")).toBe("viewer");
    expect(requiredRole("GET", "/metrics")).toBe("viewer");
    expect(requiredRole("GET", "/console/approvals")).toBe("viewer");
  });
  test("approve/deny POST -> approver", () => {
    expect(requiredRole("POST", "/console/approvals/abc/approve")).toBe("approver");
    expect(requiredRole("POST", "/console/approvals/abc/deny")).toBe("approver");
  });
  test("mutations -> admin", () => {
    expect(requiredRole("POST", "/console/revocations/claude")).toBe("admin");
    expect(requiredRole("POST", "/console/grants")).toBe("admin");
    expect(requiredRole("POST", "/console/delegations")).toBe("admin");
    expect(requiredRole("DELETE", "/console/tokens/alice")).toBe("admin");
  });
  test("/console/tokens is admin-only even for GET (sensitive roster)", () => {
    expect(requiredRole("GET", "/console/tokens")).toBe("admin");
    expect(requiredRole("POST", "/console/tokens")).toBe("admin");
  });
  test("an unrecognized route -> admin (deny-by-default)", () => {
    expect(requiredRole("POST", "/console/something-new")).toBe("admin");
    expect(requiredRole("PUT", "/console/summary")).toBe("admin"); // wrong method for a read route
  });
});
