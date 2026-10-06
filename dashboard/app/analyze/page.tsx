"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, Play, WarningDiamond, ShieldCheck } from "@phosphor-icons/react";
import { useMode } from "@/components/ModeProvider";
import { ErrorState } from "@/components/states";
import { api } from "@/lib/api";

const DEMOS = [
  {
    name: "bad" as const,
    title: "Risky change",
    body: "SSH open to the internet, an IAM policy with Action * on Resource *, a public-read S3 bucket, an unencrypted RDS instance, and an EC2 instance behind the open security group.",
    expect: "Expected: blocked",
    icon: WarningDiamond,
    tone: "text-red-400",
  },
  {
    name: "good" as const,
    title: "Safe change",
    body: "A tagged S3 bucket with a CloudWatch alarm on its size. No exposure, no IAM changes.",
    expect: "Expected: auto-approved",
    icon: ShieldCheck,
    tone: "text-emerald-400",
  },
];

const STEPS = [
  "Parse the Terraform plan",
  "Evaluate OPA policies",
  "Diff the before/after resource graph",
  "Apply the plan on MiniStack (fresh state, then reset)",
  "Price the change with Infracost",
  "Explain and sign the certificate",
];

export default function AnalyzePage() {
  const router = useRouter();
  const { mode } = useMode();
  const [choice, setChoice] = useState<"bad" | "good">("bad");
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearInterval(timer.current);
  }, []);

  async function run() {
    setRunning(true);
    setError(null);
    setElapsed(0);
    const started = Date.now();
    timer.current = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    try {
      const cert = await api.runDemo(choice);
      router.push(`/certificates/${cert.plan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setRunning(false);
    } finally {
      if (timer.current) clearInterval(timer.current);
    }
  }

  const demo = mode === "demo";
  return (
    <div className="flex max-w-4xl flex-col gap-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-balance text-2xl font-semibold tracking-tight text-zinc-50">New Analysis</h1>
        <p className="text-sm text-zinc-400">Run a bundled Terraform demo through the full GhostOps pipeline.</p>
      </div>

      <fieldset className="grid gap-3 md:grid-cols-2" disabled={running}>
        <legend className="sr-only">Choose a demo</legend>
        {DEMOS.map((d) => {
          const selected = choice === d.name;
          const Icon = d.icon;
          return (
            <label
              key={d.name}
              className={`flex cursor-pointer flex-col gap-2 rounded-md border px-4 py-4 transition-colors duration-150 ease-[var(--ease-snap)] focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-cyan-400 ${
                selected ? "border-cyan-400/70 bg-cyan-400/[0.05]" : "border-line bg-surface hover:border-line-strong"
              }`}
            >
              <input type="radio" name="demo" value={d.name} checked={selected} onChange={() => setChoice(d.name)} className="sr-only" />
              <span className="flex items-center gap-2">
                <Icon size={18} weight="bold" className={d.tone} aria-hidden="true" />
                <span className="font-medium text-zinc-100">{d.title}</span>
                <span className="ml-auto font-mono text-xs text-zinc-500">demo/{d.name}</span>
              </span>
              <span className="text-sm leading-relaxed text-zinc-400">{d.body}</span>
              <span className={`text-xs ${d.tone}`}>{d.expect}</span>
            </label>
          );
        })}
      </fieldset>

      {demo ? (
        <div className="flex flex-col gap-3 rounded-md border border-amber-400/30 bg-amber-400/[0.06] px-4 py-4">
          <p className="text-sm text-amber-200">Running an analysis needs the GhostOps API, which is not reachable (demo mode).</p>
          <Link href="/" className="flex w-max items-center gap-1.5 text-sm text-cyan-300 hover:text-cyan-200">
            View Sample Certificates <ArrowRight size={14} aria-hidden="true" />
          </Link>
        </div>
      ) : (
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => void run()}
            disabled={running || mode !== "live"}
            className="flex items-center gap-2 rounded-md bg-cyan-400 px-4 py-2.5 text-sm font-medium text-zinc-950 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-cyan-300 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Play size={16} weight="fill" aria-hidden="true" /> {running ? "Running…" : "Run Analysis"}
          </button>
          {running && (
            <span className="font-mono text-sm tabular-nums text-zinc-400" aria-live="polite">
              {elapsed}s elapsed, usually 30 to 120 s
            </span>
          )}
        </div>
      )}

      {running && (
        <div className="rounded-md border border-line bg-surface px-4 py-4" aria-busy="true">
          <p className="mb-3 text-xs text-zinc-500">GhostOps is running these steps on the server:</p>
          <ol className="flex flex-col gap-2">
            {STEPS.map((s, i) => (
              <li key={s} className="flex items-center gap-3 text-sm text-zinc-300">
                <span className="font-mono text-xs text-zinc-600">{String(i + 1).padStart(2, "0")}</span>
                {s}
              </li>
            ))}
          </ol>
          <div className="mt-4 h-0.5 overflow-hidden rounded bg-raised">
            <div className="skeleton h-full w-full" />
          </div>
        </div>
      )}

      {error && (
        <ErrorState
          title="Analysis failed"
          detail={error}
          hint="Check that the API and MiniStack are running (python -m app.server, docker compose up -d), then retry."
          onRetry={() => void run()}
        />
      )}
    </div>
  );
}
