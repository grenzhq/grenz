"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { AlertTriangle, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { StateToggle } from "@/components/state-toggle";
import { useConsole } from "@/components/console-data";
import { buildReview, type ReviewItem } from "@/lib/review";
import { applyCapability, type CapState, type EditorGrant } from "@/lib/capabilities";
import { timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";

interface PolicyDoc {
  editable: boolean;
  grants: EditorGrant[];
  digest: string;
}

const BASH = "bash";

export default function SetupPage() {
  const router = useRouter();
  const { requests, nowTick } = useConsole();
  const [doc, setDoc] = useState<PolicyDoc | null>(null);
  const [choices, setChoices] = useState<Record<string, CapState>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      const res = await fetch("/api/policy", { cache: "no-store" });
      if (res.ok) setDoc((await res.json()) as PolicyDoc);
    })();
  }, []);

  const review = useMemo(() => buildReview(requests), [requests]);

  // The suggestions are the starting position; a click replaces one of them.
  const stateOf = (item: ReviewItem): CapState => choices[item.cap.id] ?? item.suggested;
  const set = (id: string, next: CapState) => setChoices((c) => ({ ...c, [id]: next }));

  const all = [...review.flagged, ...review.routine];
  const tally = all.reduce(
    (acc, i) => {
      acc[stateOf(i)] += 1;
      return acc;
    },
    { allow: 0, ask: 0, block: 0 } as Record<CapState, number>,
  );

  const apply = async () => {
    if (!doc) return;
    setBusy(true);
    setError(null);
    try {
      const existing = doc.grants.find((g) => g.tool === BASH);
      let grant: EditorGrant = existing
        ? structuredClone(existing)
        : { tool: BASH, allow: [], require_approval: [], deny: [] };
      for (const item of all) grant = applyCapability(grant, item.cap.id, stateOf(item));

      const grants = [...doc.grants.filter((g) => g.tool !== BASH), grant];
      const res = await fetch("/api/policy", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grants, dryRun: false, baseDigest: doc.digest }),
      });
      if (!res.ok) {
        const body = (await res.json()) as { error?: string; detail?: string };
        setError(`${body.detail ?? body.error ?? res.status}. Nothing was written.`);
        return;
      }
      router.push("/permissions");
    } catch {
      setError("Couldn't reach the proxy. Nothing was written.");
    } finally {
      setBusy(false);
    }
  };

  const nothingYet = review.total === 0;

  return (
    <div className="flex min-w-0 flex-1 flex-col items-center p-8">
      <div className="flex w-full max-w-[920px] flex-col gap-5">
        <div>
          <h1 className="text-[30px] leading-tight font-semibold tracking-tight">
            Here is what your agent actually did.
          </h1>
          <p className="text-muted-foreground mt-2.5 max-w-[74ch] text-[14.5px] leading-relaxed">
            Rather than predicting what your agent will need, decide from what it already tried.
            Answer these once and it becomes your policy — every answer is changeable afterwards.
          </p>
        </div>

        {nothingYet ? (
          <Card className="items-center gap-2 py-12 text-center">
            <Shield className="text-muted-foreground/60 size-5" />
            <div className="text-[14.5px] font-medium">Nothing recorded yet.</div>
            <p className="text-muted-foreground max-w-[54ch] text-[13px]">
              Run your agent for a while with the proxy watching —{" "}
              <code className="font-mono">grenz run --shadow</code> decides and records every
              command but forwards it anyway, so nothing breaks while you gather a picture.
            </p>
            <Link href="/permissions" className="text-primary mt-2 text-[13px] font-medium">
              Or set permissions by hand →
            </Link>
          </Card>
        ) : (
          <>
            <div className="bg-border grid grid-cols-3 gap-px overflow-hidden rounded-xl border">
              <Stat n={review.total} label="commands recorded" />
              <Stat n={all.length} label="different kinds of thing" />
              <Stat
                n={review.flagged.length}
                label="worth your attention"
                tone={review.flagged.length > 0 ? "text-held-foreground" : undefined}
              />
            </div>

            {review.flagged.length > 0 && (
              <section>
                <div className="flex items-baseline gap-2.5 px-0.5 pb-2.5">
                  <span className="text-[14px] font-semibold">
                    Start with {review.flagged.length === 1 ? "this one" : `these ${review.flagged.length}`}
                  </span>
                  <span className="text-muted-foreground text-[12.5px]">the rest looked routine</span>
                </div>
                <div className="flex flex-col gap-2.5">
                  {review.flagged.map((item) => (
                    <Card key={item.cap.id} className="border-held/30 gap-0 overflow-hidden py-0">
                      <div className="flex items-start gap-3.5 px-[18px] py-4">
                        <span className="bg-held/12 text-held-foreground mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg">
                          <AlertTriangle className="size-3.5" />
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="text-[14px] font-semibold">{item.cap.name}</div>
                          <p className="text-muted-foreground mt-1 text-[13px] leading-relaxed">
                            {item.why}
                          </p>
                        </div>
                        <div className="flex shrink-0 flex-col items-end gap-1.5">
                          <span className="text-muted-foreground text-[11px]">
                            Grenz suggests {label(item.suggested)}
                          </span>
                          <StateToggle
                            label={item.cap.name}
                            value={stateOf(item)}
                            onChange={(next) => set(item.cap.id, next)}
                          />
                        </div>
                      </div>
                      <div className="bg-card-inset border-border-soft border-t px-[18px] py-3">
                        <div className="text-muted-foreground text-[11.5px]">
                          Seen {item.count === 1 ? "once" : `${item.count} times`}, last{" "}
                          {timeAgo(item.lastSeen, nowTick)} ago
                        </div>
                        <div className="mt-1.5 flex flex-col gap-1">
                          {item.examples.map((e) => (
                            <div key={e} className="truncate font-mono text-[11.5px]">
                              {e}
                            </div>
                          ))}
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </section>
            )}

            {review.routine.length > 0 && (
              <section>
                <div className="flex items-baseline gap-2.5 px-0.5 pb-2.5">
                  <span className="text-[14px] font-semibold">Everything else</span>
                  <span className="text-muted-foreground text-[12.5px]">
                    already set the way most people leave it
                  </span>
                </div>
                <Card className="gap-0 overflow-hidden py-0">
                  {review.routine.map((item) => (
                    <div
                      key={item.cap.id}
                      className="border-border-soft flex items-center gap-4 border-b px-[18px] py-3 last:border-b-0"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="text-[13.5px] font-medium">{item.cap.name}</div>
                        <div className="text-muted-foreground mt-0.5 truncate font-mono text-[11.5px]">
                          {item.examples[0]}
                        </div>
                      </div>
                      <span className="text-muted-foreground shrink-0 text-[11.5px]">
                        {item.count === 1 ? "once" : `${item.count} times`}
                      </span>
                      <StateToggle
                        label={item.cap.name}
                        value={stateOf(item)}
                        onChange={(next) => set(item.cap.id, next)}
                      />
                    </div>
                  ))}
                </Card>
              </section>
            )}

            {review.unrecognized > 0 && (
              <p className="text-muted-foreground text-[12.5px]">
                {review.unrecognized}{" "}
                {review.unrecognized === 1 ? "command has" : "commands have"} no capability name, so
                nothing is proposed for {review.unrecognized === 1 ? "it" : "them"} — they stay
                denied by default until you write a rule.
              </p>
            )}

            {error && (
              <div className="border-deny/30 bg-deny/10 text-deny-foreground rounded-lg border px-3.5 py-2.5 text-[12.5px]">
                {error}
              </div>
            )}

            <Card className="flex-row items-center gap-4 px-[18px] py-4">
              <div className="min-w-0">
                <div className="text-secondary-foreground text-[13px] font-medium">
                  {tally.allow} allowed · {tally.ask} ask first · {tally.block} blocked
                </div>
                <div className="text-muted-foreground mt-0.5 text-[12px]">
                  Anything your agent tries that is not on this list gets refused.
                </div>
              </div>
              <Link
                href="/permissions"
                className="text-muted-foreground hover:text-foreground ml-auto shrink-0 text-[12.5px]"
              >
                Skip
              </Link>
              <Button
                className="h-[38px] shrink-0 px-5 text-[13.5px] font-semibold"
                disabled={busy || !doc?.editable}
                onClick={() => void apply()}
              >
                {busy ? "…" : "Turn on protection"}
              </Button>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function label(s: CapState): string {
  return s === "allow" ? "Allow" : s === "ask" ? "Ask me" : "Block";
}

function Stat({ n, label, tone }: { n: number; label: string; tone?: string }) {
  return (
    <div className="bg-card px-[18px] py-4">
      <div className={cn("text-[25px] leading-none font-semibold tracking-tight", tone)}>{n}</div>
      <div className="text-muted-foreground mt-1.5 text-[12.5px]">{label}</div>
    </div>
  );
}
