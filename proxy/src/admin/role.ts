/**
 * Console/admin RBAC roles. Admin-plane access control (separation of duties) —
 * NOT an audit trail. `requiredRole` is deny-by-default: any route not
 * explicitly matched requires `admin`, so a console route added later without a
 * declared role is admin-only until its author lowers it — never a silent
 * fall-through to a lower role. Pure.
 */
export type Role = "viewer" | "approver" | "admin";

export const RANK: Record<Role, number> = { viewer: 0, approver: 1, admin: 2 };

export function hasRole(have: Role, need: Role): boolean {
  return RANK[have] >= RANK[need];
}

export function requiredRole(method: string, path: string): Role {
  // The operator roster is sensitive — admin-only, even to read.
  if (path === "/console/tokens" || path.startsWith("/console/tokens/")) return "admin";
  if (method === "GET" && (path === "/metrics" || path.startsWith("/console/"))) return "viewer";
  if (method === "POST" && /^\/console\/approvals\/[^/]+\/(approve|deny)$/.test(path)) return "approver";
  return "admin";
}
