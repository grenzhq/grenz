import { cn } from "@/lib/utils";

/**
 * The KPI lattice: cells sharing hairline rules rather than floating as cards.
 *
 * The rules come from a 1px grid gap over a border-coloured background, so they
 * stay exact however the grid wraps — no per-child border bookkeeping that
 * breaks the moment a column count changes.
 */
export function StatRow({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "bg-border grid grid-cols-1 gap-px overflow-hidden rounded-xl border sm:grid-cols-2 lg:grid-cols-4",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function Stat({
  label,
  value,
  valueClassName,
  suffix,
  footer,
}: {
  label: string;
  value: React.ReactNode;
  valueClassName?: string;
  suffix?: React.ReactNode;
  footer: React.ReactNode;
}) {
  return (
    <div className="bg-card flex flex-col">
      <div className="flex-1 px-[18px] pt-4 pb-3.5">
        <div className="text-muted-foreground text-[12.5px]">{label}</div>
        <div className="mt-1.5 flex items-baseline gap-2.5">
          <span className={cn("text-[32px] leading-none font-semibold tracking-tight", valueClassName)}>
            {value}
          </span>
          {suffix && <span className="text-muted-foreground text-[12.5px]">{suffix}</span>}
        </div>
      </div>
      <div className="bg-card-inset flex items-center gap-1.5 border-t px-[18px] py-2.5 text-xs">
        {footer}
      </div>
    </div>
  );
}
