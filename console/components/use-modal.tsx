"use client";

import { useCallback, useState, type ReactNode } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

/**
 * In-app confirm/prompt dialogs — the console's own surface, never the browser's
 * native `confirm()`/`prompt()`. Those break the design, read as a security
 * warning ("127.0.0.1 says…"), and can't carry a destructive tone or a
 * type-to-confirm guard. `useModal()` returns promise-based `confirm`/`prompt`
 * so the call sites stay imperative (`if (await confirm(...))`), plus the `node`
 * to render once per page.
 */

export interface ConfirmOptions {
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** `danger` paints the confirm button red — for revoke/cut-off actions. */
  tone?: "danger" | "brand";
}

export interface PromptOptions extends ConfirmOptions {
  fieldLabel?: string;
  placeholder?: string;
  defaultValue?: string;
  /** When set, confirm stays disabled until the field matches this exactly —
   *  the type-the-id guard for a blast-radius action. */
  requireMatch?: string;
}

type Pending =
  | { mode: "confirm"; opts: ConfirmOptions; resolve: (v: boolean) => void }
  | { mode: "prompt"; opts: PromptOptions; resolve: (v: string | null) => void };

export function useModal() {
  const [pending, setPending] = useState<Pending | null>(null);
  const [value, setValue] = useState("");

  const confirm = useCallback(
    (opts: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setValue("");
        setPending({ mode: "confirm", opts, resolve });
      }),
    [],
  );

  const prompt = useCallback(
    (opts: PromptOptions) =>
      new Promise<string | null>((resolve) => {
        setValue(opts.defaultValue ?? "");
        setPending({ mode: "prompt", opts, resolve });
      }),
    [],
  );

  const settle = useCallback(
    (confirmed: boolean) => {
      setPending((p) => {
        if (p) {
          if (p.mode === "confirm") p.resolve(confirmed);
          else p.resolve(confirmed ? value : null);
        }
        return null;
      });
    },
    [value],
  );

  const isPrompt = pending?.mode === "prompt";
  const requireMatch = isPrompt ? (pending.opts as PromptOptions).requireMatch : undefined;
  const matched = !requireMatch || value.trim() === requireMatch;

  const node = (
    <AlertDialog open={pending !== null} onOpenChange={(open) => !open && settle(false)}>
      {pending && (
        <AlertDialogContent className="sm:max-w-[440px]">
          <AlertDialogHeader>
            <AlertDialogTitle>{pending.opts.title}</AlertDialogTitle>
            {pending.opts.body && (
              <AlertDialogDescription asChild>
                <div className="text-muted-foreground text-[13px]">{pending.opts.body}</div>
              </AlertDialogDescription>
            )}
          </AlertDialogHeader>

          {isPrompt && (
            <div className="flex flex-col gap-2">
              {(pending.opts as PromptOptions).fieldLabel && (
                <Label htmlFor="modal-field" className="text-[12.5px]">
                  {(pending.opts as PromptOptions).fieldLabel}
                </Label>
              )}
              <Input
                id="modal-field"
                autoFocus
                value={value}
                placeholder={(pending.opts as PromptOptions).placeholder}
                onChange={(e) => setValue(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && matched) {
                    e.preventDefault();
                    settle(true);
                  }
                }}
              />
            </div>
          )}

          <AlertDialogFooter>
            <AlertDialogCancel>{pending.opts.cancelLabel ?? "Cancel"}</AlertDialogCancel>
            <AlertDialogAction
              disabled={!matched}
              onClick={() => settle(true)}
              className={cn(
                (pending.opts.tone ?? "brand") === "danger" &&
                  "bg-deny text-background hover:bg-deny/90",
              )}
            >
              {pending.opts.confirmLabel ?? "Confirm"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      )}
    </AlertDialog>
  );

  return { confirm, prompt, node };
}
