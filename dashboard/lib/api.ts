// Talks to the GhostOps FastAPI backend. If the API is unreachable, the
// dashboard switches to demo mode and reads /public/sample-certificates.

import type { Certificate, CertificateSummary, Decision, Severity, VerifyResult } from "./types";
import { SEVERITIES } from "./types";

export const API_BASE = (process.env.NEXT_PUBLIC_GHOSTOPS_API ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const SAMPLE_BASE = "/sample-certificates";

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}, timeoutMs = 15000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, signal: controller.signal, cache: "no-store" });
  } catch {
    const reason = controller.signal.aborted ? `timed out after ${Math.round(timeoutMs / 1000)}s` : "unreachable";
    throw new ApiError(`GhostOps API ${reason} (${API_BASE})`);
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
      else if (Array.isArray(body?.detail)) detail = body.detail.map((d: { msg?: string }) => d.msg).join("; ");
    } catch {
      /* body was not JSON; keep the status text */
    }
    throw new ApiError(detail, response.status);
  }
  return (await response.json()) as T;
}

export async function apiReachable(): Promise<boolean> {
  try {
    await request<{ status: string }>("/health", {}, 2500);
    return true;
  } catch {
    return false;
  }
}

export const api = {
  listCertificates: () => request<CertificateSummary[]>("/certificates"),
  getCertificate: (planId: string) => request<Certificate>(`/certificates/${planId}`),
  verify: (planId: string) => request<VerifyResult>(`/verify/${planId}`),
  decisions: (planId: string) => request<Decision[]>(`/certificates/${planId}/decisions`),
  decide: (planId: string, decision: "approve" | "deny", reviewer: string, comment: string) =>
    request<Decision & { applied: false; note: string }>(`/certificates/${planId}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, reviewer, comment: comment || null }),
    }),
  // A shadow apply on MiniStack takes 30-120 s, so allow plenty of time.
  runDemo: (name: "bad" | "good") =>
    request<Certificate>(`/analyze/demo/${name}`, { method: "POST" }, 300000),
};

// --- demo mode ------------------------------------------------------------------------------

export async function loadSampleCertificates(): Promise<Certificate[]> {
  const index = await fetch(`${SAMPLE_BASE}/index.json`, { cache: "no-store" });
  if (!index.ok) throw new ApiError("sample certificates are missing from /public/sample-certificates");
  const { files } = (await index.json()) as { files: string[] };
  return Promise.all(
    files.map(async (file) => {
      const res = await fetch(`${SAMPLE_BASE}/${file}`, { cache: "no-store" });
      if (!res.ok) throw new ApiError(`sample certificate ${file} could not be loaded`);
      return (await res.json()) as Certificate;
    }),
  );
}

export function summarize(cert: Certificate): CertificateSummary {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const flag of cert.blast_radius.risk_flags) counts[flag.severity] += 1;
  return {
    plan_id: cert.plan_id,
    timestamp: cert.timestamp,
    verdict: cert.verdict,
    generated_by: cert.generated_by,
    resource_change_count: cert.resource_changes.length,
    risk_flag_counts: counts,
    monthly_usd: cert.cost_delta.monthly_usd,
    shadow_applied: cert.shadow_run.applied,
    latest_decision: null,
  };
}
