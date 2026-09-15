"use client";

import { useCallback, useEffect, useState } from "react";
import { Nav, PageHead } from "../Nav";
import { useModal } from "../Modal";

type Entry = string | Record<string, unknown>;
type ListKey = "allow" | "require_approval" | "deny";

interface Grant {
  tool: string;
  allow: Entry[];
  require_approval: Entry[];
  deny: Entry[];
}

interface PolicyDoc {
  editable: boolean;
  grants: Grant[];
  advancedSections: string[];
  digest: string;
}

const LISTS: Array<{ key: ListKey; label: string; cls: string; placeholder: string }> = [
  { key: "allow", label: "Allow", cls: "allow", placeholder: "e.g. repo:read" },
  { key: "require_approval", label: "Needs approval", cls: "approval", placeholder: "e.g. issue:update" },
  { key: "deny", label: "Deny", cls: "deny", placeholder: "e.g. pr:merge" },
];

/** Starter cards for the tools Grenz ships adapters for. Seeded with safe
 *  defaults — reads allowed, irreversible actions gated behind approval — so a
 *  new user gets a working, sensible policy in one click instead of a blank card
 *  and a "now what?". These mirror the classification the proxy applies. */
interface Preset {
  tool: string;
  label: string;
  seed: { allow: string[]; require_approval: string[]; deny: string[] };
}
const PRESETS: Preset[] = [
  {
    tool: "github",
    label: "GitHub",
    seed: {
      allow: ["repo:read", "pr:read", "issue:read", "issue:write"],
      require_approval: ["pr:merge", "repo:delete", "actions:write"],
      deny: [],
    },
  },
  {
    tool: "linear",
    label: "Linear",
    seed: {
      allow: ["issue:read", "issue:create", "issue:update", "comment:create", "project:read"],
      require_approval: ["issue:delete"],
      deny: [],
    },
  },
  {
    tool: "slack",
    label: "Slack",
    seed: {
      allow: ["chat:read", "channel:read"],
      require_approval: ["chat:write", "call:*"],
      deny: [],
    },
  },
];

/** The action vocabulary each adapter understands — offered as click-to-add
 *  chips so the user picks from real action names instead of guessing at
 *  syntax. Kept in sync with the proxy's per-adapter classification. */
const SUGGESTED: Record<string, string[]> = {
  github: [
    "repo:read", "repo:write", "repo:delete", "pr:read", "pr:write", "pr:merge",
    "issue:read", "issue:write", "actions:read", "actions:write", "api:read", "api:write",
  ],
  linear: [
    "issue:read", "issue:create", "issue:update", "issue:delete",
    "comment:create", "project:read", "cycle:read",
  ],
  slack: ["chat:read", "chat:write", "channel:read", "channel:write", "call:*"],
  mcp: ["call:*"],
};

function isScoped(e: Entry): e is Record<string, unknown> {
  return typeof e === "object" && e !== null;
}
function scopedLabel(e: Record<string, unknown>): string {
  const action = typeof e.action === "string" ? e.action : "?";
  const targets = Array.isArray(e.targets) ? ` → ${(e.targets as unknown[]).join(", ")}` : "";
  return `${action}${targets}`;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`http ${res.status}`);
  return (await res.json()) as T;
}

export default function PolicyPage() {
  const [doc, setDoc] = useState<PolicyDoc | null>(null);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [digest, setDigest] = useState<string>("");
  const [dirty, setDirty] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err" | "info"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [offline, setOffline] = useState(false);
  const [newTool, setNewTool] = useState("");
  const { confirm, node: modalNode } = useModal();

  const load = useCallback(async () => {
    try {
      const d = await getJson<PolicyDoc>("/api/policy");
      setDoc(d);
      setGrants(structuredClone(d.grants ?? []));
      setDigest(d.digest ?? "");
      setDirty(false);
      setOffline(false);
    } catch {
      setOffline(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const mutate = (fn: (g: Grant[]) => Grant[]) => {
    setGrants((prev) => fn(structuredClone(prev)));
    setDirty(true);
    setMsg(null);
  };

  const addPattern = (tool: string, key: ListKey, value: string) => {
    const v = value.trim();
    if (!v) return;
    mutate((g) => {
      const t = g.find((x) => x.tool === tool);
      if (t && !t[key].includes(v)) t[key].push(v);
      return g;
    });
  };
  const removeEntry = (tool: string, key: ListKey, idx: number) =>
    mutate((g) => {
      const t = g.find((x) => x.tool === tool);
      if (t) t[key].splice(idx, 1);
      return g;
    });
  const removeTool = async (tool: string) => {
    const t = grants.find((x) => x.tool === tool);
    const hasScoped = t && [...t.allow, ...t.require_approval, ...t.deny].some(isScoped);
    if (hasScoped) {
      const ok = await confirm({
        title: `Remove ${tool}?`,
        body: (
          <>
            This card has <b>target-scoped rules</b> that will be removed too. This isn&#39;t saved until you press
            Save.
          </>
        ),
        confirmLabel: "Remove",
        tone: "danger",
      });
      if (!ok) return;
    }
    mutate((g) => g.filter((x) => x.tool !== tool));
  };
  const addTool = () => {
    const name = newTool.trim();
    if (!name) return;
    if (grants.some((g) => g.tool === name)) {
      setMsg({ kind: "err", text: `A card for "${name}" already exists.` });
      return;
    }
    mutate((g) => [...g, { tool: name, allow: [], require_approval: [], deny: [] }]);
    setNewTool("");
  };
  const addPreset = (p: Preset) => {
    if (grants.some((g) => g.tool === p.tool)) {
      setMsg({ kind: "info", text: `A "${p.tool}" card already exists — scroll down to edit it.` });
      return;
    }
    mutate((g) => [
      ...g,
      {
        tool: p.tool,
        allow: [...p.seed.allow],
        require_approval: [...p.seed.require_approval],
        deny: [...p.seed.deny],
      },
    ]);
    setMsg({ kind: "info", text: `Added ${p.label} with safe defaults — review, then Save to apply.` });
  };

  const send = async (dryRun: boolean) => {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/policy", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grants, dryRun, baseDigest: digest }),
      });
      const body = (await res.json()) as { error?: string; detail?: string; digest?: string; grants?: number };
      if (res.ok) {
        if (dryRun) {
          setMsg({ kind: "ok", text: `Valid — compiles to ${body.grants} grant(s).` });
        } else {
          setMsg({ kind: "ok", text: "Saved. The live policy reloaded." });
          if (body.digest) setDigest(body.digest);
          setDirty(false);
        }
      } else if (res.status === 409 && body.error === "stale_edit") {
        setMsg({ kind: "err", text: "The policy changed on disk — reloaded the latest. Re-apply your edit." });
        await load();
      } else if (res.status === 400) {
        setMsg({ kind: "err", text: `Rejected: ${body.detail ?? body.error}. Nothing was written.` });
      } else {
        setMsg({ kind: "err", text: body.error ?? `Failed (${res.status}).` });
      }
    } catch {
      setMsg({ kind: "err", text: "Couldn't reach the proxy." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Nav />
      <div className="wrap">
        <PageHead title="Policy">
        The rules every agent is held to. An agent may do what&#39;s in <span className="allow">Allow</span>, needs your
        sign-off for anything in <span className="appr">Needs approval</span>, and is blocked by{" "}
        <span className="deny">Deny</span> — everything else is denied by default. Edit below and{" "}
        <b>Save to apply instantly</b>, no restart.
      </PageHead>

      {offline && (
        <div className="offline">
          Can’t reach the Grenz proxy. Start it with <code>grenz run</code>.
        </div>
      )}

      {doc && !doc.editable && (
        <div className="offline info">
          This policy is managed remotely (a signed <code>policy_source</code>) and is read-only here. Edit it at
          the source and it will be redistributed.
        </div>
      )}

      {doc?.editable && (
        <>
          <div className="pol-toolbar">
            <div className="pol-presets">
              <span className="pol-presets-l">Add tool</span>
              {PRESETS.map((p) => {
                const exists = grants.some((g) => g.tool === p.tool);
                return (
                  <button
                    key={p.tool}
                    type="button"
                    className="pol-preset"
                    onClick={() => addPreset(p)}
                    disabled={exists}
                    title={exists ? "Already added" : `Add ${p.label} with safe defaults`}
                  >
                    + {p.label}
                  </button>
                );
              })}
              <span className="pol-add">
                <input
                  value={newTool}
                  onChange={(e) => setNewTool(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addTool()}
                  placeholder="custom…"
                  aria-label="new tool name"
                />
                <button onClick={addTool} disabled={!newTool.trim()}>
                  + Add
                </button>
              </span>
            </div>
            <div className="pol-actions">
              <button onClick={() => void send(true)} disabled={busy}>
                Validate
              </button>
              <button className="save" onClick={() => void send(false)} disabled={busy || !dirty}>
                {busy ? "…" : "Save"}
              </button>
            </div>
          </div>

          {msg && <div className={`pol-msg ${msg.kind}`}>{msg.text}</div>}

          {grants.length === 0 ? (
            <div className="pol-empty">
              <div className="pol-empty-t">No policy yet</div>
              <div className="pol-empty-b">
                Start from a tool Grenz knows — reads allowed, irreversible actions gated behind your approval.
                Everything else is denied by default. Tune it, then Save.
              </div>
              <div className="pol-empty-row">
                {PRESETS.map((p) => (
                  <button key={p.tool} type="button" className="pol-preset lg" onClick={() => addPreset(p)}>
                    + {p.label}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="pol-grid">
              {grants.map((g) => (
                <div className="pol-card" key={g.tool}>
                  <div className="pol-card-head">
                    <span className="pol-tool">{g.tool}</span>
                    <button className="pol-x" onClick={() => void removeTool(g.tool)} aria-label={`remove ${g.tool}`}>
                      ×
                    </button>
                  </div>
                  {LISTS.map(({ key, label, cls, placeholder }) => (
                    <div className="pol-list" key={key}>
                      <div className={`pol-list-label ${cls}`}>{label}</div>
                      <div className="pol-chips">
                        {g[key].length === 0 && <span className="pol-none">—</span>}
                        {g[key].map((e, i) =>
                          isScoped(e) ? (
                            <span className="pol-chip scoped" key={`s${i}`} title="target-scoped — edit in YAML">
                              {scopedLabel(e)} <span className="pol-scoped-tag">scoped</span>
                            </span>
                          ) : (
                            <span className={`pol-chip ${cls}`} key={`e${i}`}>
                              {e}
                              <button className="pol-chip-x" onClick={() => removeEntry(g.tool, key, i)} aria-label={`remove ${e}`}>
                                ×
                              </button>
                            </span>
                          ),
                        )}
                      </div>
                      <input
                        className="pol-input"
                        placeholder={placeholder}
                        onKeyDown={(ev) => {
                          if (ev.key === "Enter") {
                            addPattern(g.tool, key, (ev.target as HTMLInputElement).value);
                            (ev.target as HTMLInputElement).value = "";
                          }
                        }}
                        aria-label={`add ${label} pattern to ${g.tool}`}
                      />
                      {(() => {
                        // Offer the adapter's real action names as click-to-add
                        // chips — only the ones not already used in any list, so
                        // the same action never lands in two buckets.
                        const vocab = SUGGESTED[g.tool] ?? [];
                        if (vocab.length === 0) return null;
                        const used = new Set(
                          [...g.allow, ...g.require_approval, ...g.deny].filter(
                            (e): e is string => typeof e === "string",
                          ),
                        );
                        const picks = vocab.filter((s) => !used.has(s)).slice(0, 5);
                        if (picks.length === 0) return null;
                        return (
                          <div className="pol-sugg">
                            {picks.map((s) => (
                              <button
                                key={s}
                                type="button"
                                className={`pol-sugg-chip ${cls}`}
                                onClick={() => addPattern(g.tool, key, s)}
                                title={`Add ${s} to ${label}`}
                              >
                                + {s}
                              </button>
                            ))}
                          </div>
                        );
                      })()}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {(doc.advancedSections?.length ?? 0) > 0 && (
            <div className="pol-note">
              Preserved as-is (edit in <code>policy.yaml</code>): {doc.advancedSections.join(", ")}. Saving here
              keeps these — and your comments — untouched.
            </div>
          )}
        </>
      )}
      {modalNode}
      </div>
    </>
  );
}
