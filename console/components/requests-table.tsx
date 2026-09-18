"use client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DecisionBadge } from "@/components/decision-badge";
import { timeAgo } from "@/lib/format";
import type { RequestRow } from "@/lib/types";
import { cn } from "@/lib/utils";

/** A row is identified by when it happened plus what it was: the admin API
 *  returns no id, and two identical actions in the same millisecond would be
 *  the same decision anyway. */
export function rowKey(r: RequestRow, i: number): string {
  return `${r.ts}-${r.tool}:${r.action}-${i}`;
}

export function RequestsTable({
  rows,
  now,
  selected,
  onSelect,
  showReason = false,
  emptyMessage = "No requests yet.",
}: {
  rows: RequestRow[];
  now: number;
  selected?: RequestRow | null;
  onSelect?: (r: RequestRow) => void;
  showReason?: boolean;
  emptyMessage?: string;
}) {
  if (rows.length === 0) {
    return (
      <div className="text-muted-foreground flex flex-1 items-center justify-center px-5 py-12 text-[13px]">
        {emptyMessage}
      </div>
    );
  }

  return (
    <Table className="table-fixed">
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="w-[68px] pl-[18px]">When</TableHead>
          <TableHead className="w-[104px]">Agent</TableHead>
          <TableHead className="w-[146px]">Action</TableHead>
          <TableHead>Target</TableHead>
          {showReason && <TableHead className="w-[150px]">Reason</TableHead>}
          <TableHead className="w-[100px] pr-[18px] text-right">Decision</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((r, i) => {
          const isSelected = selected === r;
          return (
            <TableRow
              key={rowKey(r, i)}
              tabIndex={onSelect ? 0 : undefined}
              data-state={isSelected ? "selected" : undefined}
              onClick={onSelect ? () => onSelect(r) : undefined}
              onKeyDown={
                onSelect
                  ? (e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSelect(r);
                      }
                    }
                  : undefined
              }
              className={cn("border-border-soft", onSelect && "cursor-pointer")}
            >
              <TableCell className="text-muted-foreground pl-[18px] font-mono">
                {timeAgo(r.ts, now)}
              </TableCell>
              <TableCell className="text-secondary-foreground truncate">{r.agentId}</TableCell>
              <TableCell className="truncate font-mono">
                {r.tool}:{r.action}
              </TableCell>
              <TableCell className="text-muted-foreground truncate font-mono" title={r.target}>
                {r.target}
              </TableCell>
              {showReason && (
                <TableCell className="text-muted-foreground truncate font-mono text-[11.5px]" title={r.reason}>
                  {r.reason}
                </TableCell>
              )}
              <TableCell className="pr-[18px] text-right">
                <DecisionBadge decision={r.decision} />
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
