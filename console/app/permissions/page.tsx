"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AlertTriangle, ChevronDown, ChevronRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/page-header";
import { StateToggle } from "@/components/state-toggle";
import { useModal } from "@/components/use-modal";
import {
  BASH_CAPABILITIES,
  GROUPS,
  applyCapability,
  losesScope,
  readCapabilities,
  type CapState,
  type EditorGrant,
} from "@/lib/capabilities";
import { cn } from "@/lib/utils";

interface PolicyDoc {
  editable: boolean;
  grants: EditorGrant[];
  advancedSections: string[];
  digest: string;
}

type Msg = { kind: "ok" | "err"; text: string };

const BASH = "bash";

export default function PermissionsPage() {
  const [doc, setDoc] = useState<PolicyDoc | null>(null);
  const [grants, setGrants] = useState<EditorGrant[]>([]);
  const [digest, setDigest] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [offline, setOffline] = useState(false);
  const [msg, setMsg] = useState<Msg | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const { confirm, node: modalNode } = useModal();

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/policy", { cache: "no-store" });
      if (!res.ok) throw new Error(`http ${res.status}`);
      const d = (await res.json()) as PolicyDoc;
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

  const bash = grants.find((g) => g.tool === BASH);
  const view = useMemo(() => readCapabilities(bash), [bash]);

  const change = async (capId: string, next: CapState) => {
    const row = view.rows.find((r) => r.cap.id === capId);
    if (row && losesScope(row, next)) {
      const ok = await confirm({
        title: `Block ${row.cap.name.toLowerCase()}?`,
        body: (
          <>
            This capability is currently limited to <b>{row.narrowedTo} specific targets</b>. A
            block has to be unscoped to be absolute, so those limits are replaced by a flat
            refusal. Nothing is written until you press Save.
          </>
        ),
        confirmLabel: "Block it",
        tone: "danger",
      });
      if (!ok) return;
    }
    setGrants((prev) => {
      const current = prev.find((g) => g.tool === BASH) ?? {
        tool: BASH,
        allow: [],
        require_approval: [],
        deny: [],
      };
      const updated = applyCapability(current, capId, next);
      const rest = prev.filter((g) => g.tool !== BASH);
      return [...rest, updated];
    });
    setDirty(true);
    setMsg(null);
  };

  const save = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/policy", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grants, dryRun: false, baseDigest: digest }),
      });
      const body = (await res.json()) as { error?: string; detail?: string; digest?: string };
      if (res.ok) {
        setMsg({ kind: "ok", text: "Saved. It applies to the next command." });
        if (body.digest) setDigest(body.digest);
        setDirty(false);
      } else if (res.status === 409 && body.error === "stale_edit") {
        setMsg({ kind: "err", text: "The policy changed on disk — reloaded it. Re-apply your change." });
        await load();
      } else {
        setMsg({ kind: "err", text: `Rejected: ${body.detail ?? body.error}. Nothing was written.` });
      }
    } catch {
      setMsg({ kind: "err", text: "Couldn't reach the proxy." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <div className="flex items-start gap-4">
        <PageHeader title="Permissions">
          What your agents are allowed to do on this machine. Changes apply to the next command;
          nothing needs restarting.
        </PageHeader>
        <div className="ml-auto flex shrink-0 items-center gap-2">
          {dirty && <span className="text-held-foreground text-[12.5px]">Unsaved changes</span>}
          <Button size="sm" className="h-[30px]" disabled={busy || !dirty} onClick={() => void save()}>
            {busy ? "…" : "Save"}
          </Button>
        </div>
      </div>

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
            It arrives as a signed <code className="font-mono">policy_source</code>, so it is
            read-only here. Change it at the source and it will be redistributed.
          </AlertDescription>
        </Alert>
      )}

      {msg && (
        <div
          className={cn(
            "rounded-lg border px-3.5 py-2.5 text-[12.5px]",
            msg.kind === "ok"
              ? "border-allow/30 bg-allow/10 text-allow-foreground"
              : "border-deny/30 bg-deny/10 text-deny-foreground",
          )}
        >
          {msg.text}
        </div>
      )}

      <Card className="flex-row items-center gap-3.5 px-4 py-3.5">
        <span className="bg-primary/10 text-primary flex size-[30px] shrink-0 items-center justify-center rounded-lg">
          <ShieldCheck className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="text-secondary-foreground text-[13px] font-medium">
            Anything not on this list is already blocked.
          </div>
          <p className="text-muted-foreground mt-0.5 text-[12.5px]">
            You are loosening a closed door, never tightening an open one — so leaving something
            alone is always the safe choice.
          </p>
        </div>
      </Card>

      {GROUPS.map((group) => {
        const rows = view.rows.filter((r) => r.cap.group === group.id);
        if (rows.length === 0) return null;
        return (
          <div key={group.id}>
            <div className="flex items-baseline gap-2.5 px-0.5 pb-2">
              <span className="text-secondary-foreground text-[13px] font-semibold">{group.title}</span>
              <span className="text-muted-foreground text-xs">{group.note}</span>
            </div>

            <Card className="gap-0 overflow-hidden py-0">
              {rows.map((r) => {
                const expanded = open === r.cap.id;
                return (
                  <div key={r.cap.id} className="border-border-soft border-b last:border-b-0">
                    <div className="flex items-center gap-4 px-[18px] py-3.5">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[13.5px] font-medium">{r.cap.name}</span>
                          {r.present && (
                            <button
                              type="button"
                              onClick={() => setOpen(expanded ? null : r.cap.id)}
                              className="bg-accent text-muted-foreground hover:text-foreground inline-flex items-center gap-1 rounded-md px-1.5 py-px text-[11px]"
                            >
                              {r.commands.length} {r.commands.length === 1 ? "command" : "commands"}
                              {expanded ? (
                                <ChevronDown className="size-2.5" />
                              ) : (
                                <ChevronRight className="size-2.5" />
                              )}
                            </button>
                          )}
                          {r.narrowedTo > 0 && (
                            <span className="text-muted-foreground rounded-md border border-dashed px-1.5 py-px text-[11px]">
                              narrowed to {r.narrowedTo} {r.narrowedTo === 1 ? "target" : "targets"}
                            </span>
                          )}
                          {r.mixed && (
                            <span className="border-held/40 text-held-foreground rounded-md border border-dashed px-1.5 py-px text-[11px]">
                              mixed — some rules differ
                            </span>
                          )}
                          {!r.present && r.state === "block" && (
                            <span className="text-muted-foreground text-[11px]">
                              nothing written — denied by default
                            </span>
                          )}
                        </div>
                        <p className="text-muted-foreground mt-1 text-[12.5px]">{r.cap.description}</p>
                      </div>

                      <StateToggle
                        label={r.cap.name}
                        value={r.state}
                        disabled={!doc?.editable || r.mixed}
                        onChange={(next) => void change(r.cap.id, next)}
                      />
                    </div>

                    {expanded && (
                      <div className="px-[18px] pb-4">
                        <div className="bg-card-inset rounded-lg border px-3.5 py-3">
                          <div className="text-muted-foreground text-xs">This covers:</div>
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {r.commands.map((c) => (
                              <span
                                key={c}
                                className="bg-card rounded-md border px-2 py-0.5 font-mono text-[11px]"
                              >
                                {c}
                              </span>
                            ))}
                          </div>
                          <div className="mt-3 flex items-center gap-2.5 border-t pt-2.5">
                            <span className="text-muted-foreground text-xs">
                              {r.ruleCount} {r.ruleCount === 1 ? "rule" : "rules"} in your policy.
                            </span>
                            <Link
                              href="/policy"
                              className="text-primary ml-auto shrink-0 text-xs font-medium"
                            >
                              Edit as rules →
                            </Link>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </Card>
          </div>
        );
      })}

      <div>
        <div className="flex items-baseline gap-2.5 px-0.5 pb-2">
          <span className="text-secondary-foreground text-[13px] font-semibold">Your own rules</span>
          <span className="text-muted-foreground text-xs">
            no name above fits these, so they are shown as written
          </span>
        </div>
        <Card className="gap-0 overflow-hidden border-dashed py-0">
          <p className="text-muted-foreground border-b px-[18px] py-3 text-[12.5px]">
            These still apply exactly as they are. Nothing on this page rewrites them — a rule that
            cannot be named is shown, not flattened into one that is approximately right.
          </p>
          {view.leftovers.length === 0 ? (
            <div className="text-muted-foreground px-[18px] py-6 text-center text-[13px]">
              Every rule in your policy has a name above.
            </div>
          ) : (
            view.leftovers.map((l, i) => (
              <div
                key={`${l.clause}-${l.action}-${i}`}
                className="border-border-soft flex items-start gap-3.5 border-b px-[18px] py-3 last:border-b-0"
              >
                <span className="w-24 shrink-0 pt-0.5 font-mono text-[11.5px]">{l.action}</span>
                <div className="flex min-w-0 flex-1 flex-wrap gap-1.5">
                  {l.targets.length === 0 ? (
                    <span className="text-muted-foreground text-[11.5px]">any target</span>
                  ) : (
                    l.targets.map((t) => (
                      <span
                        key={t}
                        className="bg-card-inset rounded-md border px-2 py-0.5 font-mono text-[11px]"
                      >
                        {t}
                      </span>
                    ))
                  )}
                </div>
                <span
                  className={cn(
                    "shrink-0 pt-0.5 text-[11.5px]",
                    l.state === "allow" && "text-allow-foreground",
                    l.state === "ask" && "text-held-foreground",
                    l.state === "block" && "text-deny-foreground",
                  )}
                >
                  {l.state === "allow" ? "Allowed" : l.state === "ask" ? "Asks first" : "Blocked"}
                </span>
                <Link href="/policy" className="text-primary shrink-0 pt-0.5 text-[11.5px] font-medium">
                  Edit
                </Link>
              </div>
            ))
          )}
        </Card>
      </div>

      <Card className="flex-row flex-wrap items-center gap-x-6 gap-y-2 px-[18px] py-3.5">
        <Legend tone="bg-allow" name="Allow" text="runs without interrupting you" />
        <Legend
          tone="bg-held"
          name="Ask me"
          text="the agent waits. No answer in 5 minutes and it is refused"
        />
        <Legend tone="bg-deny" name="Block" text="refused, and a temporary grant cannot reopen it" />
        <Link href="/policy" className="text-primary ml-auto shrink-0 text-[12.5px] font-medium">
          Advanced: edit rules →
        </Link>
      </Card>

      {modalNode}
    </div>
  );
}

function Legend({ tone, name, text }: { tone: string; name: string; text: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={cn("size-2 rounded-[2px]", tone)} />
      <span className="text-muted-foreground text-[12.5px]">
        <span className="text-secondary-foreground">{name}</span> — {text}
      </span>
    </div>
  );
}
