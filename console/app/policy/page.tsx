"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/page-header";
import { useModal } from "@/components/use-modal";
import { cn } from "@/lib/utils";

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

const LISTS: Array<{
  key: ListKey;
  label: string;
  placeholder: string;
  labelClass: string;
  chipClass: string;
}> = [
  {
    key: "allow",
    label: "Allow",
    placeholder: "e.g. repo:read",
    labelClass: "text-allow-foreground",
    chipClass: "border-allow/30 bg-allow/10 text-allow-foreground",
  },
  {
    key: "require_approval",
    label: "Needs approval",
    placeholder: "e.g. issue:update",
    labelClass: "text-held-foreground",
    chipClass: "border-held/30 bg-held/10 text-held-foreground",
  },
  {
    key: "deny",
    label: "Deny",
    placeholder: "e.g. pr:merge",
    labelClass: "text-deny-foreground",
    chipClass: "border-deny/30 bg-deny/10 text-deny-foreground",
  },
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
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <PageHeader title="Policy">
        The rules every agent is held to. An agent may do what&#39;s in{" "}
        <span className="text-allow-foreground font-medium">Allow</span>, needs your sign-off for
        anything in <span className="text-held-foreground font-medium">Needs approval</span>, and is
        blocked by <span className="text-deny-foreground font-medium">Deny</span> — everything else
        is denied by default. Saving applies instantly, no restart.
      </PageHeader>

      {offline && (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertTitle>Can&rsquo;t reach the Grenz proxy.</AlertTitle>
          <AlertDescription>
            Start it with <code className="font-mono">grenz run</code>.
          </AlertDescription>
        </Alert>
      )}

      {doc && !doc.editable && (
        <Alert>
          <AlertTitle>This policy is managed remotely.</AlertTitle>
          <AlertDescription>
            It arrives as a signed <code className="font-mono">policy_source</code> and is read-only
            here. Edit it at the source and it will be redistributed.
          </AlertDescription>
        </Alert>
      )}

      {doc?.editable && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground mr-1 text-[12.5px]">Add tool</span>
            {PRESETS.map((p) => {
              const exists = grants.some((g) => g.tool === p.tool);
              return (
                <Button
                  key={p.tool}
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-[30px]"
                  onClick={() => addPreset(p)}
                  disabled={exists}
                  title={exists ? "Already added" : `Add ${p.label} with safe defaults`}
                >
                  <Plus className="size-3.5" />
                  {p.label}
                </Button>
              );
            })}
            <div className="flex items-center gap-1.5">
              <Input
                value={newTool}
                onChange={(e) => setNewTool(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addTool()}
                placeholder="custom…"
                aria-label="New tool name"
                className="h-[30px] w-[130px] text-[12.5px]"
              />
              <Button size="sm" variant="outline" className="h-[30px]" onClick={addTool} disabled={!newTool.trim()}>
                Add
              </Button>
            </div>

            <div className="ml-auto flex items-center gap-2">
              <Button size="sm" variant="outline" className="h-[30px]" onClick={() => void send(true)} disabled={busy}>
                Validate
              </Button>
              <Button size="sm" className="h-[30px]" onClick={() => void send(false)} disabled={busy || !dirty}>
                {busy ? "…" : "Save"}
              </Button>
            </div>
          </div>

          {msg && (
            <div
              className={cn(
                "rounded-lg border px-3.5 py-2.5 text-[12.5px]",
                msg.kind === "ok" && "border-allow/30 bg-allow/10 text-allow-foreground",
                msg.kind === "err" && "border-deny/30 bg-deny/10 text-deny-foreground",
                msg.kind === "info" && "bg-muted text-muted-foreground",
              )}
            >
              {msg.text}
            </div>
          )}

          {grants.length === 0 ? (
            <Card className="items-center gap-2 py-10 text-center">
              <div className="text-[14.5px] font-medium">No policy yet</div>
              <p className="text-muted-foreground max-w-[56ch] text-[13px]">
                Start from a tool Grenz knows — reads allowed, irreversible actions gated behind your
                approval. Everything else is denied by default. Tune it, then Save.
              </p>
              <div className="mt-2 flex flex-wrap justify-center gap-2">
                {PRESETS.map((p) => (
                  <Button key={p.tool} type="button" variant="outline" onClick={() => addPreset(p)}>
                    <Plus className="size-4" />
                    {p.label}
                  </Button>
                ))}
              </div>
            </Card>
          ) : (
            <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2 2xl:grid-cols-3">
              {grants.map((g) => (
                <Card key={g.tool} className="min-w-0 gap-0 overflow-hidden py-0">
                  <CardHeader className="items-center border-b px-[18px] py-3">
                    <CardTitle className="truncate font-mono text-[13.5px]">{g.tool}</CardTitle>
                    <CardAction>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-[26px]"
                        onClick={() => void removeTool(g.tool)}
                        aria-label={`Remove ${g.tool}`}
                      >
                        <X className="size-3.5" />
                      </Button>
                    </CardAction>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-4 px-[18px] py-4">
                    {LISTS.map(({ key, label, placeholder, labelClass, chipClass }) => {
                      // Offer the adapter's real action names as click-to-add
                      // chips — only the ones not already used in any list, so
                      // the same action never lands in two buckets.
                      const vocab = SUGGESTED[g.tool] ?? [];
                      const used = new Set(
                        [...g.allow, ...g.require_approval, ...g.deny].filter(
                          (e): e is string => typeof e === "string",
                        ),
                      );
                      const picks = vocab.filter((s) => !used.has(s)).slice(0, 5);
                      return (
                        <div key={key} className="flex flex-col gap-2">
                          <div className={cn("text-[11.5px] font-medium", labelClass)}>{label}</div>
                          <div className="flex flex-wrap gap-1.5">
                            {g[key].length === 0 && (
                              <span className="text-muted-foreground text-[12px]">—</span>
                            )}
                            {g[key].map((e, i) =>
                              isScoped(e) ? (
                                <span
                                  key={`s${i}`}
                                  title="target-scoped — edit in YAML"
                                  className="bg-muted text-muted-foreground inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11.5px]"
                                >
                                  {scopedLabel(e)}
                                  <span className="text-[10px] tracking-wide uppercase opacity-70">
                                    scoped
                                  </span>
                                </span>
                              ) : (
                                <span
                                  key={`e${i}`}
                                  className={cn(
                                    "inline-flex items-center gap-1 rounded-md border py-0.5 pr-1 pl-2 font-mono text-[11.5px]",
                                    chipClass,
                                  )}
                                >
                                  {e}
                                  <button
                                    type="button"
                                    onClick={() => removeEntry(g.tool, key, i)}
                                    aria-label={`Remove ${e}`}
                                    className="hover:bg-foreground/10 rounded-sm p-0.5"
                                  >
                                    <X className="size-3" />
                                  </button>
                                </span>
                              ),
                            )}
                          </div>
                          <Input
                            placeholder={placeholder}
                            onKeyDown={(ev) => {
                              if (ev.key === "Enter") {
                                addPattern(g.tool, key, (ev.target as HTMLInputElement).value);
                                (ev.target as HTMLInputElement).value = "";
                              }
                            }}
                            aria-label={`Add ${label} pattern to ${g.tool}`}
                            className="h-[30px] font-mono text-[12px]"
                          />
                          {picks.length > 0 && (
                            <div className="flex flex-wrap gap-1.5">
                              {picks.map((s) => (
                                <button
                                  key={s}
                                  type="button"
                                  onClick={() => addPattern(g.tool, key, s)}
                                  title={`Add ${s} to ${label}`}
                                  className="border-border text-muted-foreground hover:bg-accent hover:text-foreground inline-flex items-center gap-1 rounded-md border border-dashed px-2 py-0.5 font-mono text-[11px]"
                                >
                                  <Plus className="size-2.5" />
                                  {s}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {(doc.advancedSections?.length ?? 0) > 0 && (
            <p className="text-muted-foreground text-[12.5px]">
              Preserved as-is (edit in <code className="font-mono">policy.yaml</code>):{" "}
              {doc.advancedSections.join(", ")}. Saving here keeps these — and your comments —
              untouched.
            </p>
          )}
        </>
      )}
      {modalNode}
    </div>
  );
}
