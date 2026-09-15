"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

const TABS = [
  { href: "/", label: "Overview" },
  { href: "/policy", label: "Policy" },
  { href: "/access", label: "Access" },
];

/** The one navigation surface, shared by every page. It shows where you are
 *  (active tab) and where you can go, so the three views read as one app. */
export function Nav({ right }: { right?: ReactNode }) {
  const path = usePathname();
  return (
    <div className="navdock">
      <header className="appbar">
        <Link className="brand" href="/" aria-label="Grenz — overview">
          <span className="brand-mark" />
          <span className="brand-wm">Grenz</span>
        </Link>
        <nav className="tabs" aria-label="Console sections">
          {TABS.map((t) => {
            const active = t.href === "/" ? path === "/" : path.startsWith(t.href);
            return (
              <Link
                key={t.href}
                href={t.href}
                className={`tab${active ? " active" : ""}`}
                aria-current={active ? "page" : undefined}
              >
                {t.label}
              </Link>
            );
          })}
        </nav>
        <div className="appbar-right">{right}</div>
      </header>
    </div>
  );
}

/** A short orientation block under the nav: what this page is, and what you do
 *  here. The fix for "I landed and didn't know what to do." */
export function PageHead({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="page-head">
      <h1>{title}</h1>
      <p>{children}</p>
    </div>
  );
}
