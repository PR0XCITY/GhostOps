"use client";

import { CurrencyDollar, Lifebuoy, Lightning, ShieldCheck } from "@phosphor-icons/react";
import type { Icon } from "@phosphor-icons/react";
import { PILLARS, type Pillar, type Pillars } from "@/lib/types";

const META: Record<Pillar, { label: string; icon: Icon }> = {
  security: { label: "Security", icon: ShieldCheck },
  reliability: { label: "Reliability", icon: Lifebuoy },
  cost: { label: "Cost", icon: CurrencyDollar },
  performance: { label: "Performance", icon: Lightning },
};

// Red only where the verdict is affected (a blocking security finding); otherwise the
// score band: emerald 90+, amber 60-89, orange below 60.
function tone(score: number, blocking: boolean) {
  if (blocking) return { text: "text-red-300", bar: "bg-red-500" };
  if (score >= 90) return { text: "text-emerald-300", bar: "bg-emerald-500" };
  if (score >= 60) return { text: "text-amber-300", bar: "bg-amber-400" };
  return { text: "text-orange-300", bar: "bg-orange-500" };
}

export function PillarPanel({ pillars, stale }: { pillars: Pillars; stale: boolean }) {
  return (
    <div className={`flex flex-col gap-2 transition-opacity duration-150 ${stale ? "opacity-60" : ""}`}>
      <ul className="grid grid-cols-2 gap-2">
        {PILLARS.map((p) => {
          const { score, findings } = pillars[p];
          const blocking = p === "security" && findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
          const t = tone(score, blocking);
          const Glyph = META[p].icon;
          const rules = [...new Set(findings.map((f) => f.rule))];
          return (
            <li key={p} className="flex min-w-0 flex-col gap-1.5 rounded-md border border-line bg-canvas/60 px-2.5 py-2"
                title={rules.length ? `Lowered by ${rules.join(", ")}` : "No findings"}>
              <div className="flex items-center gap-1.5 text-xs text-zinc-300">
                <Glyph size={14} className="shrink-0 text-zinc-500" aria-hidden="true" />
                {META[p].label}
                <span className={`ml-auto text-[10px] ${p === "security" ? "text-zinc-400" : "text-zinc-500"}`}>
                  {p === "security" ? "can block" : "advisory"}
                </span>
              </div>
              <p className={`font-mono text-xl font-semibold tabular-nums ${t.text}`}>
                {score}<span className="text-xs font-normal text-zinc-500">/100</span>
              </p>
              <div className="h-1 overflow-hidden rounded-sm bg-raised" role="meter" aria-valuemin={0} aria-valuemax={100}
                   aria-valuenow={score} aria-label={`${META[p].label} score`}>
                <div className={`h-full ${t.bar} transition-[width] duration-150`} style={{ width: `${score}%` }} />
              </div>
              <p className="truncate font-mono text-[10px] text-zinc-500" translate="no">
                {findings.length === 0 ? "no findings" : `${findings.length} finding${findings.length === 1 ? "" : "s"}: ${rules.join(" ")}`}
              </p>
            </li>
          );
        })}
      </ul>
      <p className="text-[11px] leading-relaxed text-zinc-500">
        Score = 100 minus 40 per critical, 25 per high, 10 per medium and 5 per low finding of that pillar.
        Only high or critical security findings block; the other pillars are advice.
      </p>
    </div>
  );
}
