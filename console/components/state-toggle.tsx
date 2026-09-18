"use client";

import type { CapState } from "@/lib/capabilities";
import { cn } from "@/lib/utils";

const OPTIONS: ReadonlyArray<{ value: CapState; label: string; on: string }> = [
  { value: "allow", label: "Allow", on: "bg-allow/15 text-allow-foreground" },
  { value: "ask", label: "Ask me", on: "bg-held/15 text-held-foreground" },
  { value: "block", label: "Block", on: "bg-deny/15 text-deny-foreground" },
];

/** Allow / Ask me / Block — the three states a capability can be in, which are
 *  the policy's three clauses wearing words a person would use. */
export function StateToggle({
  value,
  onChange,
  label,
  disabled,
}: {
  value: CapState;
  onChange: (next: CapState) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className="bg-card-inset flex w-[204px] shrink-0 gap-0.5 rounded-lg border p-[3px]"
    >
      {OPTIONS.map((o) => {
        const active = value === o.value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={disabled}
            onClick={() => onChange(o.value)}
            className={cn(
              "h-[26px] flex-1 rounded-md text-[11.5px] font-medium transition-colors",
              active ? cn(o.on, "font-semibold") : "text-muted-foreground hover:text-foreground",
              disabled && "cursor-not-allowed opacity-50",
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
