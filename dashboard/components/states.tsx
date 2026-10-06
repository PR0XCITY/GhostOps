"use client";

import { WarningOctagon } from "@phosphor-icons/react";

export function SkeletonRows({ rows = 4, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="divide-y divide-line" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="grid gap-4 px-4 py-4" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
          {Array.from({ length: cols }, (_, c) => (
            <div key={c} className="skeleton h-4 rounded" style={{ width: `${55 + ((r * 7 + c * 13) % 40)}%` }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonBlock({ className = "h-24" }: { className?: string }) {
  return <div className={`skeleton rounded-md ${className}`} aria-busy="true" />;
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 px-6 py-14">
      <p className="text-base font-medium text-zinc-200">{title}</p>
      <p className="max-w-[60ch] text-sm leading-relaxed text-zinc-400">{body}</p>
      {action}
    </div>
  );
}

export function ErrorState({ title, detail, hint, onRetry }: {
  title: string; detail: string; hint?: string; onRetry?: () => void;
}) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-md border border-red-500/40 bg-red-500/[0.07] px-4 py-4">
      <WarningOctagon size={20} weight="bold" className="mt-0.5 shrink-0 text-red-400" aria-hidden="true" />
      <div className="flex min-w-0 flex-col gap-1">
        <p className="text-sm font-medium text-red-200">{title}</p>
        <p className="break-words font-mono text-xs leading-relaxed text-red-200/80">{detail}</p>
        {hint && <p className="text-xs leading-relaxed text-zinc-300">{hint}</p>}
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="mt-2 w-max rounded-md border border-line-strong px-3 py-1.5 text-xs text-zinc-200 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-raised active:translate-y-px"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
}
