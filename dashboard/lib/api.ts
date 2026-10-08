// Talks to the GhostOps FastAPI backend. If the API is unreachable, the
// dashboard switches to demo mode and reads /public/sample-certificates.

import type {
  ArchitectureError, ArchitectureService, CatalogService, Certificate, CertificateSummary, CheckResult, Decision,
  PreviewResult, Severity, VerifyResult,
} from "./types";
import { SEVERITIES } from "./types";
import type { Comparison, SavedDesign, Slot } from "./compare";

export const API_BASE = (process.env.NEXT_PUBLIC_GHOSTOPS_API ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const SAMPLE_BASE = "/sample-certificates";
// Only for a hosted API (GHOSTOPS_HOSTED=1). NEXT_PUBLIC_* values are compiled into the
// browser bundle, so anyone who opens the dashboard can read this key: it slows down
// casual abuse of the public API, it is not authentication.
const API_KEY = process.env.NEXT_PUBLIC_GHOSTOPS_API_KEY ?? "";
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function withApiKey(init: RequestInit): RequestInit {
  if (!API_KEY || !MUTATING.has((init.method ?? "GET").toUpperCase())) return init;
  const headers = new Headers(init.headers);
  headers.set("X-GhostOps-Key", API_KEY);
  return { ...init, headers };
}

export class ApiError extends Error {
  constructor(message: string, readonly status?: number, readonly errors?: ArchitectureError[]) {
    super(message);
  }
}

export function isAbort(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

async function request<T>(path: string, init: RequestInit = {}, timeoutMs = 15000, outer?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onOuterAbort = () => controller.abort(outer?.reason);
  outer?.addEventListener("abort", onOuterAbort);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...withApiKey(init), signal: controller.signal, cache: "no-store" });
  } catch {
    if (outer?.aborted) throw new DOMException("superseded", "AbortError"); // a newer request replaced this one
    const reason = controller.signal.aborted ? `timed out after ${Math.round(timeoutMs / 1000)}s` : "unreachable";
    throw new ApiError(`GhostOps API ${reason} (${API_BASE})`);
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener("abort", onOuterAbort);
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    let errors: ArchitectureError[] | undefined;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
      else if (Array.isArray(body?.detail)) detail = body.detail.map((d: { msg?: string }) => d.msg).join("; ");
      else if (body?.detail?.errors) {
        detail = body.detail.message ?? "invalid architecture";
        errors = body.detail.errors as ArchitectureError[];
      }
    } catch {
      /* body was not JSON; keep the status text */
    }
    throw new ApiError(detail, response.status, errors);
  }
  return (await response.json()) as T;
}

function postJson<T>(path: string, body: unknown, timeoutMs: number, signal?: AbortSignal): Promise<T> {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }, timeoutMs, signal);
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
  catalog: () => request<CatalogService[]>("/catalog"),
  // Fast: Terraform text, validation errors, resources per service.
  preview: (arch: { services: ArchitectureService[] }, signal?: AbortSignal) =>
    postJson<PreviewResult>("/architectures/preview", arch, 15000, signal),
  // ~20-30 s: plan + OPA + graph + cost + fixes, no shadow apply, not stored.
  check: (arch: { services: ArchitectureService[] }, signal?: AbortSignal) =>
    postJson<CheckResult>("/architectures/check", arch, 180000, signal),
  // 40-150 s: full pipeline incl. MiniStack apply; stores a signed certificate.
  analyzeArchitecture: (arch: { services: ArchitectureService[] }, signal?: AbortSignal) =>
    postJson<Certificate>("/architectures/analyze", arch, 600000, signal),
  // Compare slots, kept in SQLite. Saving runs the static check (~20-30 s).
  comparisons: () => request<Comparison>("/comparisons"),
  saveDesign: (slot: Slot, arch: { services: ArchitectureService[] }) =>
    request<SavedDesign>(`/comparisons/${slot}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(arch),
    }, 180000),
  deleteDesign: (slot: Slot) => request<{ slot: Slot; deleted: true }>(`/comparisons/${slot}`, { method: "DELETE" }),
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
