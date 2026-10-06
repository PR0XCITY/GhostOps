"use client";

import { CheckCircle, Prohibit, SealCheck, SealWarning, Question } from "@phosphor-icons/react";
import type { Severity, Verdict } from "@/lib/types";

export const SEVERITY_STYLE: Record<Severity, { text: string; chip: string; bar: string }> = {
  CRITICAL: { text: "text-red-400", chip: "border-red-500/40 bg-red-500/15 text-red-300", bar: "bg-red-500" },
  HIGH: { text: "text-orange-400", chip: "border-orange-400/40 bg-orange-400/10 text-orange-300", bar: "bg-orange-400" },
  MEDIUM: { text: "text-amber-300", chip: "border-amber-300/30 bg-amber-300/10 text-amber-200", bar: "bg-amber-300" },
  LOW: { text: "text-zinc-400", chip: "border-zinc-500/30 bg-zinc-500/10 text-zinc-300", bar: "bg-zinc-500" },
};

export function VerdictBadge({ verdict, size = "sm" }: { verdict: Verdict; size?: "sm" | "md" }) {
  const blocked = verdict === "BLOCKED_PENDING_REVIEW";
  const pad = size === "md" ? "px-2.5 py-1 text-sm" : "px-2 py-0.5 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded border font-medium ${pad} ${
        blocked ? "border-red-500/50 bg-red-500/15 text-red-300" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
      }`}
    >
      {blocked ? <Prohibit size={14} weight="bold" /> : <CheckCircle size={14} weight="bold" />}
      {blocked ? "Blocked" : "Auto-approved"}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (!severity) return <span className="font-mono text-xs text-zinc-600">none</span>;
  return (
    <span className={`inline-flex rounded border px-1.5 py-0.5 font-mono text-[11px] font-medium ${SEVERITY_STYLE[severity].chip}`}>
      {severity}
    </span>
  );
}

export function SignatureBadge({ state }: { state: "verified" | "invalid" | "checking" | "unavailable" }) {
  const styles = {
    verified: { cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300", icon: <SealCheck size={14} weight="bold" />, label: "Signature verified" },
    invalid: { cls: "border-red-500/50 bg-red-500/15 text-red-300", icon: <SealWarning size={14} weight="bold" />, label: "Signature INVALID" },
    checking: { cls: "border-line bg-raised text-zinc-400", icon: <Question size={14} />, label: "Verifying..." },
    unavailable: { cls: "border-line bg-raised text-zinc-400", icon: <Question size={14} />, label: "Not verifiable in demo mode" },
  }[state];
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-2 py-0.5 text-xs font-medium ${styles.cls}`}>
      {styles.icon}
      {styles.label}
    </span>
  );
}
