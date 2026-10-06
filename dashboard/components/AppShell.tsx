"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheckered } from "@phosphor-icons/react";
import { useMode } from "./ModeProvider";
import { API_BASE } from "@/lib/api";

const NAV = [
  { href: "/", label: "Certificates" },
  { href: "/analyze", label: "New Analysis" },
];

function ModeIndicator() {
  const { mode, recheck } = useMode();
  if (mode === "checking") {
    return <span className="font-mono text-xs text-zinc-500">Connecting…</span>;
  }
  if (mode === "live") {
    return (
      <span className="flex items-center gap-2 font-mono text-xs text-zinc-400" title={API_BASE}>
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
        API live
      </span>
    );
  }
  return (
    <button
      type="button"
      onClick={() => void recheck()}
      className="flex items-center gap-2 rounded border border-amber-400/40 bg-amber-400/10 px-2 py-1 font-mono text-xs text-amber-300 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-amber-400/20"
      title={`API unreachable at ${API_BASE}. Showing sample certificates. Click to retry.`}
      aria-label="Demo mode: API unreachable. Retry connection"
    >
      <span className="h-1.5 w-1.5 rounded-full bg-amber-300" aria-hidden="true" />
      Demo mode
    </button>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { mode } = useMode();
  return (
    <div className="flex min-h-[100dvh] flex-col">
      <a
        href="#main"
        className="sr-only z-30 rounded-md bg-cyan-400 px-3 py-2 text-sm font-medium text-zinc-950 focus:not-sr-only focus:fixed focus:left-4 focus:top-3"
      >
        Skip to Content
      </a>
      <header className="sticky top-0 z-20 border-b border-line bg-canvas/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-8 px-4 md:px-6">
          <Link href="/" className="flex items-center gap-2 text-zinc-100" aria-label="GhostOps home">
            <ShieldCheckered size={20} weight="duotone" className="text-cyan-400" aria-hidden="true" />
            <span className="font-mono text-sm font-semibold tracking-tight" translate="no">ghostops</span>
          </Link>
          <nav className="flex items-center gap-1" aria-label="Main">
            {NAV.map((item) => {
              const active = item.href === "/" ? pathname === "/" || pathname.startsWith("/certificates") : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={`rounded-md px-3 py-1.5 text-sm transition-colors duration-150 ease-[var(--ease-snap)] ${
                    active ? "bg-raised text-zinc-100" : "text-zinc-400 hover:bg-raised/60 hover:text-zinc-100"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="ml-auto">
            <ModeIndicator />
          </div>
        </div>
      </header>
      {mode === "demo" && (
        <div className="border-b border-amber-400/20 bg-amber-400/[0.06]">
          <p className="mx-auto max-w-[1400px] px-4 py-2 text-xs text-amber-200/90 md:px-6">
            Demo mode: the GhostOps API at <span className="font-mono" translate="no">{API_BASE}</span> is unreachable,
            so these are bundled sample certificates. Start it with{" "}
            <span className="font-mono" translate="no">python -m app.server</span>.
          </p>
        </div>
      )}
      <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-8 outline-none md:px-6">
        {children}
      </main>
    </div>
  );
}
