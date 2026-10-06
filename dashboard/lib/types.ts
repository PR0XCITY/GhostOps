// Mirrors the Risk Certificate contract in CLAUDE.md / backend/app/certificate.py.
// Field names must not change: the backend signs exactly this shape.

export type Verdict = "AUTO_APPROVED" | "BLOCKED_PENDING_REVIEW";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Action = "create" | "update" | "delete" | "replace" | "no-op";

export interface ResourceChange {
  resource: string;
  action: Action;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

export interface RiskFlag {
  rule: string;
  severity: Severity;
  resource: string;
  message: string;
}

export interface NewlyPublic {
  address: string;
  type: string;
  via: string[];
}

export interface IamWidened {
  address: string;
  type: string;
  added_grants: { action: string; resource: string }[];
  removed_denies: { action: string; resource: string }[];
  admin: boolean;
  unknown: boolean;
}

export interface GraphNode {
  id: string;
  type: string;
  action: Action;
  risk: boolean;
  risk_reasons: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  via: string[];
}

export interface Certificate {
  plan_id: string;
  timestamp: string;
  resource_changes: ResourceChange[];
  blast_radius: {
    newly_public: NewlyPublic[];
    iam_widened: IamWidened[];
    risk_flags: RiskFlag[];
    graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  };
  shadow_run: { applied: boolean; resources_created: number; error: string | null };
  cost_delta: { monthly_usd: number | null; note: string | null };
  verdict: Verdict;
  risk_explanation: string;
  generated_by: "groq" | "template";
  signature: string;
}

export interface Decision {
  id: number;
  plan_id: string;
  decision: "approve" | "deny";
  reviewer: string;
  comment: string | null;
  certificate_signature: string;
  verdict_at_decision: Verdict;
  decided_at: string;
}

export interface CertificateSummary {
  plan_id: string;
  timestamp: string;
  verdict: Verdict;
  generated_by: "groq" | "template";
  resource_change_count: number;
  risk_flag_counts: Record<Severity, number>;
  monthly_usd: number | null;
  shadow_applied: boolean;
  latest_decision: { decision: "approve" | "deny"; reviewer: string; decided_at: string } | null;
}

export interface VerifyResult {
  plan_id: string;
  valid: boolean;
  verdict: Verdict;
  timestamp: string;
  signature: string;
}

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
