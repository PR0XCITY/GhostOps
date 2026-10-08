"use client";

import Link from "next/link";
import { ArrowRight } from "@phosphor-icons/react";
import { SeverityBadge, VerdictBadge } from "@/components/badges";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/states";
import { formatTimestamp, formatUsd, shortHash, topSeverity } from "@/lib/format";
import { useCertificateList } from "@/lib/useCertificates";
import type { CertificateSummary } from "@/lib/types";

function Stat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-zinc-500">{label}</span>
      <span className={`font-mono text-2xl font-semibold tabular-nums ${tone}`}>{value}</span>
    </div>
  );
}

function Row({ c }: { c: CertificateSummary }) {
  const blocked = c.verdict === "BLOCKED_PENDING_REVIEW";
  const href = `/certificates/${c.plan_id}`;
  const top = topSeverity(c.risk_flag_counts);
  const flagCount = Object.values(c.risk_flag_counts).reduce((a, b) => a + b, 0);
  return (
    <tr
      className={`border-l-2 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-raised/70 ${
        blocked ? "border-l-red-500 bg-red-500/[0.04]" : "border-l-emerald-500/70"
      }`}
    >
      <td className="px-4 py-3.5">
        <VerdictBadge verdict={c.verdict} />
      </td>
      <td className="px-4 py-3.5">
        <Link href={href} translate="no" className="font-mono text-sm text-zinc-200 underline-offset-4 hover:text-cyan-300 hover:underline">
          {shortHash(c.plan_id)}
        </Link>
        <div className="mt-0.5 text-xs text-zinc-500">
          {c.resource_change_count} change{c.resource_change_count === 1 ? "" : "s"}
          {!blocked ? (
            // Auto-approved certificates are approved by policy; no human review is involved.
            <span className="text-emerald-400/90"> · auto-approved by policy</span>
          ) : c.latest_decision ? (
            <span className={c.latest_decision.decision === "approve" ? "text-emerald-400/90" : "text-red-400/90"}>
              {" "}· {c.latest_decision.decision === "approve" ? "approved" : "denied"} by {c.latest_decision.reviewer}
            </span>
          ) : (
            <span className="text-amber-300/90"> · awaiting review</span>
          )}
        </div>
      </td>
      <td className="px-4 py-3.5">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={top} />
          {flagCount > 0 && <span className="font-mono text-xs text-zinc-500">{flagCount} flags</span>}
        </div>
      </td>
      <td className={`px-4 py-3.5 text-right font-mono text-sm tabular-nums ${c.monthly_usd === null ? "text-zinc-500" : "text-zinc-200"}`}>
        {formatUsd(c.monthly_usd)}
        {c.monthly_usd !== null && <span className="text-zinc-500">/mo</span>}
      </td>
      <td className="px-4 py-3.5 text-right font-mono text-xs text-zinc-400 tabular-nums">{formatTimestamp(c.timestamp)}</td>
      <td className="px-2 py-2">
        <Link
          href={href}
          aria-label={`Open certificate ${shortHash(c.plan_id)}`}
          className="flex h-8 w-8 items-center justify-center rounded-md text-zinc-500 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-raised hover:text-cyan-300"
        >
          <ArrowRight size={16} aria-hidden="true" />
        </Link>
      </td>
    </tr>
  );
}

export default function Home() {
  const { state, reload, mode } = useCertificateList();
  const rows = state.status === "ready" ? state.data : [];
  const blocked = rows.filter((r) => r.verdict === "BLOCKED_PENDING_REVIEW").length;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="flex flex-col gap-1">
          <h1 className="text-balance text-2xl font-semibold tracking-tight text-zinc-50">Risk Certificates</h1>
          <p className="text-sm text-zinc-400">Every Terraform plan GhostOps has checked, newest first.</p>
        </div>
        {state.status === "ready" && rows.length > 0 && (
          <div className="flex gap-10">
            <Stat label="Blocked" value={blocked} tone={blocked ? "text-red-400" : "text-zinc-300"} />
            <Stat label="Auto-approved" value={rows.length - blocked} tone="text-emerald-400" />
            <Stat label="Total" value={rows.length} tone="text-zinc-200" />
          </div>
        )}
      </div>

      <div className="overflow-hidden rounded-md border border-line bg-surface">
        {state.status === "loading" || mode === "checking" ? (
          <SkeletonRows rows={4} cols={5} />
        ) : state.status === "error" ? (
          <div className="p-4">
            <ErrorState
              title="Could not load certificates"
              detail={state.error}
              hint="Check that the GhostOps API is running (python -m app.server), then retry."
              onRetry={() => void reload()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No Certificates Yet"
            body="Build an architecture (or load an example) and press Analyze to produce your first signed Risk Certificate, or analyse a plan with the ghostops CLI."
            action={
              <Link
                href="/builder"
                className="mt-1 inline-flex items-center gap-2 rounded-md bg-cyan-400 px-3 py-2 text-sm font-medium text-zinc-950 transition-transform duration-150 ease-[var(--ease-snap)] hover:bg-cyan-300 active:translate-y-px"
              >
                Open Builder <ArrowRight size={14} weight="bold" aria-hidden="true" />
              </Link>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left">
              <thead>
                <tr className="border-b border-line text-xs text-zinc-500">
                  <th className="px-4 py-2.5 font-medium">Verdict</th>
                  <th className="px-4 py-2.5 font-medium">Plan</th>
                  <th className="px-4 py-2.5 font-medium">Top severity</th>
                  <th className="px-4 py-2.5 text-right font-medium">Cost delta</th>
                  <th className="px-4 py-2.5 text-right font-medium">Timestamp</th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((c) => (
                  <Row key={c.plan_id} c={c} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
