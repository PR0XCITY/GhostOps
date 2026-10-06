"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { ArrowLeft, CheckCircle, Prohibit, Siren, ShieldCheck } from "@phosphor-icons/react";
import { ResourceGraph } from "@/components/ResourceGraph";
import { SEVERITY_STYLE, SignatureBadge, VerdictBadge } from "@/components/badges";
import { ErrorState, SkeletonBlock } from "@/components/states";
import { api } from "@/lib/api";
import { formatTimestamp, formatUsd } from "@/lib/format";
import { useCertificate, type CertificateDetail } from "@/lib/useCertificates";
import type { Certificate, Decision } from "@/lib/types";
import { SEVERITIES } from "@/lib/types";

function Panel({ title, children, className = "", tone = "neutral" }: {
  title: React.ReactNode; children: React.ReactNode; className?: string; tone?: "neutral" | "alarm";
}) {
  const alarm = tone === "alarm";
  return (
    <section className={`overflow-hidden rounded-md border ${alarm ? "border-red-500/60 bg-red-500/[0.06]" : "border-line bg-surface"} ${className}`}>
      <h2 className={`flex items-center gap-2 border-b px-4 py-2.5 text-sm font-medium ${alarm ? "border-red-500/40 text-red-200" : "border-line text-zinc-300"}`}>
        {title}
      </h2>
      {children}
    </section>
  );
}

function VerdictBanner({ cert }: { cert: Certificate }) {
  const blocked = cert.verdict === "BLOCKED_PENDING_REVIEW";
  const flags = cert.blast_radius.risk_flags;
  const crit = flags.filter((f) => f.severity === "CRITICAL").length;
  const high = flags.filter((f) => f.severity === "HIGH").length;
  return (
    <div
      className={`flex flex-col gap-4 rounded-md border-l-4 px-5 py-5 md:flex-row md:items-center ${
        blocked ? "border border-red-500/50 border-l-red-500 bg-red-500/10" : "border border-emerald-500/40 border-l-emerald-500 bg-emerald-500/[0.07]"
      }`}
    >
      <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-md ${blocked ? "bg-red-500/20 text-red-300" : "bg-emerald-500/15 text-emerald-300"}`}>
        {blocked ? <Prohibit size={28} weight="bold" /> : <ShieldCheck size={28} weight="bold" />}
      </div>
      <div className="flex flex-col gap-1">
        <p className={`font-mono text-xl font-semibold tracking-tight ${blocked ? "text-red-200" : "text-emerald-200"}`}>
          {blocked ? "BLOCKED PENDING REVIEW" : "AUTO-APPROVED"}
        </p>
        <p className={`text-sm ${blocked ? "text-red-200/80" : "text-emerald-200/80"}`}>
          {blocked
            ? crit + high > 0
              ? `${crit} critical and ${high} high-severity findings. A human must approve or deny this change.`
              : "The change could not be verified, so a human must review it."
            : "No critical or high-severity findings, and the shadow apply succeeded."}
        </p>
      </div>
    </div>
  );
}

function BlastRadius({ cert }: { cert: Certificate }) {
  const { newly_public, iam_widened } = cert.blast_radius;
  const count = newly_public.length + iam_widened.length;
  if (count === 0) {
    return (
      <Panel title={<><ShieldCheck size={16} className="text-emerald-400" /> Blast radius</>}>
        <p className="px-4 py-4 text-sm text-zinc-400">No resource becomes reachable from the internet and no IAM permission widens.</p>
      </Panel>
    );
  }
  return (
    <Panel tone="alarm" title={<><Siren size={16} weight="fill" className="text-red-400" /> Blast radius: {count} risk{count === 1 ? "" : "s"}</>}>
      <ul className="divide-y divide-red-500/20">
        {newly_public.map((p) => (
          <li key={`pub-${p.address}`} className="flex flex-col gap-0.5 px-4 py-3">
            <span className="font-mono text-sm text-red-100">{p.address}</span>
            <span className="text-xs text-red-200/80">
              Newly reachable from 0.0.0.0/0 via <span className="font-mono">{p.via.join(", ")}</span>
            </span>
          </li>
        ))}
        {iam_widened.map((w) => (
          <li key={`iam-${w.address}`} className="flex flex-col gap-0.5 px-4 py-3">
            <span className="font-mono text-sm text-red-100">{w.address}</span>
            <span className="text-xs text-red-200/80">
              {w.unknown
                ? "IAM policy only known after apply: cannot be checked"
                : w.admin
                  ? "IAM widened to full admin (Action * on Resource *)"
                  : `IAM grants ${w.added_grants.length} new permission(s)`}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function RiskFlags({ cert }: { cert: Certificate }) {
  const flags = cert.blast_radius.risk_flags;
  return (
    <Panel title={<>Risk flags <span className="font-mono text-xs text-zinc-500">{flags.length}</span></>}>
      {flags.length === 0 ? (
        <p className="px-4 py-4 text-sm text-zinc-400">No policy, exposure, IAM or shadow-run findings.</p>
      ) : (
        <ul className="divide-y divide-line">
          {flags.map((f, i) => (
            <li key={`${f.rule}-${f.resource}-${i}`} className="grid grid-cols-[4px_1fr] gap-x-3 px-4 py-3">
              <span className={`row-span-2 rounded-full ${SEVERITY_STYLE[f.severity].bar}`} aria-hidden />
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className={`font-mono text-xs font-semibold ${SEVERITY_STYLE[f.severity].text}`}>{f.severity}</span>
                <span className="font-mono text-xs text-zinc-400">{f.rule}</span>
                <span className="font-mono text-xs text-zinc-200">{f.resource}</span>
              </div>
              <p className="text-sm leading-relaxed text-zinc-300">{f.message}</p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function Facts({ cert }: { cert: Certificate }) {
  const { cost_delta: cost, shadow_run: shadow } = cert;
  const counts = SEVERITIES.map((s) => ({ s, n: cert.blast_radius.risk_flags.filter((f) => f.severity === s).length }));
  return (
    <Panel title="Summary">
      <dl className="divide-y divide-line text-sm">
        <div className="flex flex-col gap-1 px-4 py-3">
          <dt className="text-xs text-zinc-500">Monthly cost delta</dt>
          <dd className={`font-mono text-2xl font-semibold tabular-nums ${cost.monthly_usd === null ? "text-zinc-500" : "text-zinc-100"}`}>
            {formatUsd(cost.monthly_usd)}
            {cost.monthly_usd !== null && <span className="text-sm font-normal text-zinc-500"> /month</span>}
          </dd>
          {cost.note && <p className="text-xs leading-relaxed text-zinc-500">{cost.note}</p>}
        </div>
        <div className="flex flex-col gap-1 px-4 py-3">
          <dt className="text-xs text-zinc-500">Shadow run on MiniStack</dt>
          <dd className={shadow.applied ? "text-emerald-300" : "text-red-300"}>
            {shadow.applied ? `Applied: ${shadow.resources_created} resources created` : "Not applied"}
          </dd>
          {shadow.error && <pre className="whitespace-pre-wrap break-words font-mono text-xs text-red-200/80">{shadow.error}</pre>}
        </div>
        <div className="flex flex-col gap-2 px-4 py-3">
          <dt className="text-xs text-zinc-500">Findings by severity</dt>
          <dd className="grid grid-cols-4 gap-2">
            {counts.map(({ s, n }) => (
              <div key={s} className="flex flex-col">
                <span className={`font-mono text-lg tabular-nums ${n ? SEVERITY_STYLE[s].text : "text-zinc-600"}`}>{n}</span>
                <span className="text-[10px] text-zinc-500">{s.toLowerCase()}</span>
              </div>
            ))}
          </dd>
        </div>
        <div className="flex flex-col gap-1 px-4 py-3">
          <dt className="text-xs text-zinc-500">Changes</dt>
          <dd className="text-zinc-200">{cert.resource_changes.length} resource change{cert.resource_changes.length === 1 ? "" : "s"}</dd>
        </div>
      </dl>
    </Panel>
  );
}

function DecisionPanel({ detail, demo, onDecided }: { detail: CertificateDetail; demo: boolean; onDecided: (d: Decision) => void }) {
  const { cert, verify, decisions } = detail;
  const [reviewer, setReviewer] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const blocked = cert.verdict === "BLOCKED_PENDING_REVIEW";
  const invalid = verify !== null && !verify.valid;
  const disabled = demo || invalid || busy !== null;

  async function decide(decision: "approve" | "deny") {
    if (!reviewer.trim()) {
      setError("Enter your name as the reviewer first.");
      return;
    }
    setBusy(decision);
    setError(null);
    try {
      onDecided(await api.decide(cert.plan_id, decision, reviewer.trim(), comment.trim()));
      setComment("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Panel title="Review">
      {blocked && (
        <div className="flex flex-col gap-3 px-4 py-4">
          {demo && <p className="text-xs text-amber-300/90">Decisions need the live API. Demo mode is read-only.</p>}
          {invalid && <p className="text-xs text-red-300">The signature is invalid, so decisions are disabled.</p>}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="reviewer" className="text-xs text-zinc-400">Reviewer</label>
            <input
              id="reviewer"
              value={reviewer}
              onChange={(e) => setReviewer(e.target.value)}
              maxLength={100}
              disabled={disabled}
              className="rounded-md border border-line-strong bg-canvas px-3 py-2 text-sm text-zinc-100 outline-none transition-colors focus:border-cyan-400 disabled:opacity-50"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="comment" className="text-xs text-zinc-400">Comment (optional)</label>
            <textarea
              id="comment"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              maxLength={1000}
              rows={2}
              disabled={disabled}
              className="resize-none rounded-md border border-line-strong bg-canvas px-3 py-2 text-sm text-zinc-100 outline-none transition-colors focus:border-cyan-400 disabled:opacity-50"
            />
          </div>
          {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => void decide("approve")}
              disabled={disabled}
              className="flex items-center justify-center gap-1.5 rounded-md border border-emerald-500/60 px-3 py-2 text-sm font-medium text-emerald-300 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-emerald-500/10 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40"
            >
              <CheckCircle size={16} weight="bold" /> {busy === "approve" ? "Saving..." : "Approve"}
            </button>
            <button
              type="button"
              onClick={() => void decide("deny")}
              disabled={disabled}
              className="flex items-center justify-center gap-1.5 rounded-md bg-red-500 px-3 py-2 text-sm font-medium text-white transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-red-400 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Prohibit size={16} weight="bold" /> {busy === "deny" ? "Saving..." : "Deny"}
            </button>
          </div>
          <p className="text-[11px] leading-relaxed text-zinc-500">
            Decisions go to the append-only audit log. GhostOps never applies changes to any real system.
          </p>
        </div>
      )}
      <div className={blocked ? "border-t border-line" : ""}>
        <p className="px-4 pt-3 text-xs text-zinc-500">Audit log</p>
        {decisions.length === 0 ? (
          <p className="px-4 pb-4 pt-1 text-sm text-zinc-500">{blocked ? "No decision yet." : "Auto-approved: no review needed."}</p>
        ) : (
          <ul className="divide-y divide-line pb-1">
            {decisions.map((d) => (
              <li key={d.id} className="flex flex-col gap-0.5 px-4 py-2.5">
                <span className="flex items-center gap-2 text-sm">
                  <span className={`font-medium ${d.decision === "approve" ? "text-emerald-300" : "text-red-300"}`}>
                    {d.decision === "approve" ? "Approved" : "Denied"}
                  </span>
                  <span className="text-zinc-300">by {d.reviewer}</span>
                </span>
                <span className="font-mono text-[11px] text-zinc-500">{formatTimestamp(d.decided_at)}</span>
                {d.comment && <span className="text-xs text-zinc-400">{d.comment}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}

function ResourceChanges({ cert }: { cert: Certificate }) {
  const tone: Record<string, string> = {
    create: "text-emerald-300", update: "text-amber-200", delete: "text-red-300", replace: "text-orange-300", "no-op": "text-zinc-500",
  };
  return (
    <Panel title={<>Resource changes <span className="font-mono text-xs text-zinc-500">{cert.resource_changes.length}</span></>}>
      <ul className="divide-y divide-line">
        {cert.resource_changes.map((rc) => (
          <li key={rc.resource}>
            <details className="group">
              <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-2.5 hover:bg-raised/60">
                <span className={`w-16 font-mono text-xs ${tone[rc.action] ?? "text-zinc-400"}`}>{rc.action}</span>
                <span className="font-mono text-sm text-zinc-200">{rc.resource}</span>
              </summary>
              <pre className="max-h-80 overflow-auto border-t border-line bg-canvas px-4 py-3 font-mono text-xs leading-relaxed text-zinc-400">
                {JSON.stringify(rc.after ?? rc.before, null, 2)}
              </pre>
            </details>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export default function CertificatePage() {
  const { planId } = useParams<{ planId: string }>();
  const { state, reload, mode, setState } = useCertificate(planId);

  if (state.status === "loading" || mode === "checking") {
    return (
      <div className="flex flex-col gap-4">
        <SkeletonBlock className="h-6 w-64" />
        <SkeletonBlock className="h-24" />
        <SkeletonBlock className="h-20" />
        <div className="grid gap-4 lg:grid-cols-3">
          <SkeletonBlock className="h-96 lg:col-span-2" />
          <SkeletonBlock className="h-96" />
        </div>
      </div>
    );
  }
  if (state.status === "error") {
    return (
      <div className="flex flex-col gap-4">
        <Link href="/" className="flex w-max items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-100">
          <ArrowLeft size={14} /> Certificates
        </Link>
        <ErrorState title="Could not load this certificate" detail={state.error} onRetry={() => void reload()} />
      </div>
    );
  }

  const detail = state.data;
  const { cert, verify } = detail;
  const signature = mode === "demo" ? "unavailable" : verify?.valid ? "verified" : "invalid";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Link href="/" className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-100">
          <ArrowLeft size={14} /> Certificates
        </Link>
        <span className="font-mono text-xs text-zinc-500" title={cert.plan_id}>plan {cert.plan_id}</span>
        <span className="font-mono text-xs text-zinc-500">{formatTimestamp(cert.timestamp)}</span>
        <div className="ml-auto flex items-center gap-2">
          <VerdictBadge verdict={cert.verdict} />
          <SignatureBadge state={signature} />
        </div>
      </div>

      <VerdictBanner cert={cert} />

      <div className="flex flex-col gap-2">
        <p className="max-w-[80ch] text-xl leading-relaxed text-zinc-100 md:text-2xl md:leading-relaxed">{cert.risk_explanation}</p>
        <p className="font-mono text-[11px] text-zinc-500">
          explanation: {cert.generated_by === "groq" ? "Groq (from sanitized findings only)" : "template"}
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="flex flex-col gap-4 lg:col-span-2">
          <BlastRadius cert={cert} />
          <Panel title="Resource graph (after this change)">
            <ResourceGraph nodes={cert.blast_radius.graph.nodes} edges={cert.blast_radius.graph.edges} />
          </Panel>
          <RiskFlags cert={cert} />
          <ResourceChanges cert={cert} />
        </div>
        <div className="flex flex-col gap-4">
          <DecisionPanel
            detail={detail}
            demo={mode === "demo"}
            onDecided={(d) => setState({ status: "ready", data: { ...detail, decisions: [...detail.decisions, d] } })}
          />
          <Facts cert={cert} />
          <Panel title="Signature">
            <div className="flex flex-col gap-2 px-4 py-3">
              <SignatureBadge state={signature} />
              <p className="break-all font-mono text-[11px] text-zinc-500">HMAC-SHA256 {cert.signature}</p>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
