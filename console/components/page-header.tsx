export function PageHeader({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
      {children && <p className="text-muted-foreground text-[13.5px]">{children}</p>}
    </div>
  );
}

/** A section that has nothing in it yet says so inside its card, in one line —
 *  never as a full-width band competing with the panels that do have content. */
export function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-muted-foreground px-5 py-8 text-center text-[13px]">{children}</div>
  );
}
