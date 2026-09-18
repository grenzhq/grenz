"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * Dark/light without a theme library.
 *
 * The console is one local page with one viewer, so `next-themes` would be a
 * dependency bought for a class toggle. `THEME_INIT` below runs before paint to
 * keep the first frame from flashing the wrong theme; this component only
 * mirrors and flips what that script already decided.
 */
export const THEME_INIT = `(function(){try{var t=localStorage.getItem("grenz-theme");var d=t?t==="dark":matchMedia("(prefers-color-scheme: dark)").matches;document.documentElement.classList.toggle("dark",d)}catch(e){}})()`;

export function ThemeToggle() {
  const [dark, setDark] = useState(true);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
  }, []);

  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("grenz-theme", next ? "dark" : "light");
    } catch {
      // Private-mode storage failures shouldn't cost you the toggle.
    }
  };

  return (
    <Button
      variant="ghost"
      size="icon"
      className="size-[30px]"
      onClick={toggle}
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
    >
      {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  );
}
