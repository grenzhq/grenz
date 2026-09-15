"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

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

  const node = pending ? (
    <ModalView
      pending={pending}
      value={value}
      onValue={setValue}
      onCancel={() => settle(false)}
      onConfirm={() => settle(true)}
    />
  ) : null;

  return { confirm, prompt, node };
}

function ModalView({
  pending,
  value,
  onValue,
  onCancel,
  onConfirm,
}: {
  pending: Pending;
  value: string;
  onValue: (v: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const { opts } = pending;
  const inputRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);

  const isPrompt = pending.mode === "prompt";
  const requireMatch = isPrompt ? (opts as PromptOptions).requireMatch : undefined;
  const matched = !requireMatch || value.trim() === requireMatch;

  // Focus the field (prompt) or the confirm button (confirm) on open, and trap
  // Esc → cancel for the whole dialog.
  useEffect(() => {
    (isPrompt ? inputRef.current : confirmRef.current)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isPrompt, onCancel]);

  const tone = opts.tone ?? "brand";

  return (
    <div className="modal-scrim" onMouseDown={onCancel} role="presentation">
      <div
        className="modal"
        role="alertdialog"
        aria-modal="true"
        aria-label={opts.title}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modal-title">{opts.title}</div>
        {opts.body && <div className="modal-body">{opts.body}</div>}

        {isPrompt && (
          <label className="modal-field">
            {(opts as PromptOptions).fieldLabel && (
              <span className="modal-field-l">{(opts as PromptOptions).fieldLabel}</span>
            )}
            <input
              ref={inputRef}
              value={value}
              placeholder={(opts as PromptOptions).placeholder}
              onChange={(e) => onValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && matched) {
                  e.preventDefault();
                  onConfirm();
                }
              }}
            />
          </label>
        )}

        <div className="modal-actions">
          <button className="modal-btn" onClick={onCancel}>
            {opts.cancelLabel ?? "Cancel"}
          </button>
          <button
            ref={confirmRef}
            className={`modal-btn primary ${tone}`}
            disabled={!matched}
            onClick={onConfirm}
          >
            {opts.confirmLabel ?? "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}
