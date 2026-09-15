"use client";

import { useEffect } from "react";

export interface ReqDetail {
  ts: number;
  agentId: string;
  tool: string;
  action: string;
  target: string;
  method?: string;
  upstream?: string;
  decision: string;
  reason: string;
  forwarded: boolean;
  status?: number | null;
  count?: number;
  shadow?: boolean;
}

const DECISION_LABEL: Record<string, string> = {
  allow: "Allowed",
  deny: "Denied",
  require_approval: "Held for approval",
};

/** Click a request → the full story of that one decision, plus the two things
 *  you'd do about it: change the rule, or act on the agent. A slide-over so it
 *  never loses the list behind it. */
export function RequestDrawer({ req, onClose }: { req: ReqDetail | null; onClose: () => void }) {
  useEffect(() => {
    if (!req) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [req, onClose]);

  if (!req) return null;
  const when = new Date(req.ts).toLocaleString([], { dateStyle: "medium", timeStyle: "medium" });
  const status = req.forwarded ? (req.status ?? "—") : "blocked at the door";

  const rows: Array<[string, React.ReactNode]> = [
    ["Agent", <span className="mono">{req.agentId}</span>],
    ["Action", <span className="mono">{req.tool}:{req.action}</span>],
    ["Target", <span className="mono wrap">{req.target || "—"}</span>],
    ...(req.method ? ([["Method", <span className="mono">{req.method}</span>]] as Array<[string, React.ReactNode]>) : []),
    ["Reason", <span className="mono">{req.reason}</span>],
    ["Result", <span className="mono">{status}</span>],
    ["When", <span>{when}</span>],
    ...(req.count && req.count > 1 ? ([["Seen", <span>{req.count}× (coalesced)</span>]] as Array<[string, React.ReactNode]>) : []),
  ];

  return (
    <div className="drawer-scrim" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Request detail">
        <div className="drawer-head">
          <span className={`badge ${req.decision}`}>{DECISION_LABEL[req.decision] ?? req.decision}</span>
          <button className="drawer-x" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="drawer-title mono">
          {req.tool}:{req.action}
        </div>

        <dl className="drawer-rows">
          {rows.map(([k, v]) => (
            <div className="drawer-row" key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>

        <div className="drawer-actions">
          <span className="drawer-actions-l">Act on this</span>
          <a className="drawer-act" href="/policy">
            Change the rule for <span className="mono">{req.tool}:{req.action}</span> →
          </a>
          <a className="drawer-act" href="/access">
            Manage <span className="mono">{req.agentId}</span> — revoke or grant →
          </a>
        </div>
      </aside>
    </div>
  );
}
