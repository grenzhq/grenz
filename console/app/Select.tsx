"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * A custom listbox — the native <select> menu can't be styled to match the
 * console, so we render our own with the same design tokens as the drawer.
 * Full keyboard support (Arrow/Home/End/Enter/Esc), click-outside to close,
 * and a selected checkmark, so it behaves like the native control it replaces.
 */

export interface SelectOption {
  value: string;
  label: string;
  hint?: string;
}

export function Select({
  value,
  onChange,
  options,
  placeholder = "Select…",
  ariaLabel,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  options: SelectOption[];
  placeholder?: string;
  ariaLabel?: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const selectedIdx = options.findIndex((o) => o.value === value);
  const selected = selectedIdx >= 0 ? options[selectedIdx] : undefined;

  const openMenu = useCallback(() => {
    setActive(selectedIdx >= 0 ? selectedIdx : 0);
    setOpen(true);
  }, [selectedIdx]);

  const commit = useCallback(
    (idx: number) => {
      const opt = options[idx];
      if (opt) onChange(opt.value);
      setOpen(false);
    },
    [options, onChange],
  );

  // Click / focus outside closes the menu.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open]);

  // Keep the active option scrolled into view.
  useEffect(() => {
    if (open) listRef.current?.children[active]?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const onKey = (e: React.KeyboardEvent) => {
    if (!open) {
      if (e.key === "Enter" || e.key === " " || e.key === "ArrowDown") {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    switch (e.key) {
      case "Escape":
        e.preventDefault();
        setOpen(false);
        break;
      case "ArrowDown":
        e.preventDefault();
        setActive((i) => Math.min(options.length - 1, i + 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        break;
      case "Home":
        e.preventDefault();
        setActive(0);
        break;
      case "End":
        e.preventDefault();
        setActive(options.length - 1);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        commit(active);
        break;
    }
  };

  return (
    <div ref={rootRef} className={`sel${open ? " open" : ""}${className ? ` ${className}` : ""}`}>
      <button
        type="button"
        className={`sel-btn${selected ? "" : " placeholder"}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => (open ? setOpen(false) : openMenu())}
        onKeyDown={onKey}
      >
        <span className="sel-val">{selected ? selected.label : placeholder}</span>
        <svg className="sel-chevron" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
          <path d="M2.5 4.5 6 8l3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <ul ref={listRef} className="sel-menu" role="listbox" aria-label={ariaLabel} tabIndex={-1}>
          {options.map((o, i) => (
            <li
              key={o.value}
              role="option"
              aria-selected={o.value === value}
              className={`sel-opt${i === active ? " active" : ""}${o.value === value ? " selected" : ""}`}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => {
                e.preventDefault();
                commit(i);
              }}
            >
              <span className="sel-opt-l">{o.label}</span>
              {o.hint && <span className="sel-opt-hint">{o.hint}</span>}
              <svg className="sel-check" width="13" height="13" viewBox="0 0 13 13" aria-hidden="true">
                <path d="M2.5 6.8 5 9.2l5.5-5.6" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
