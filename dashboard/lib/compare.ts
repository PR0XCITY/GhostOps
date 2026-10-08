// Compare slots A and B (GET/PUT/DELETE /comparisons). Types mirror backend/app/compare.py.

import type { ArchitectureService, Pillar, Pillars, Severity, Verdict } from "./types";

export type Slot = "A" | "B";
export const SLOTS: Slot[] = ["A", "B"];

export interface DesignSnapshot {
  monthly_usd: number | null;
  cost_note: string | null;
  verdict: Verdict; // static check only: not signed, no MiniStack apply
  pillars: Pillars;
  risk_count: number;
  blocking_count: number; // security CRITICAL/HIGH
  penalty: number;
  risk_flags: { rule: string; severity: Severity; resource: string; pillar: Pillar }[];
  resource_count: number;
  services: { name: string; type: string; monthly_usd: number | null }[];
}

export interface SavedDesign {
  slot: Slot;
  architecture: { services: ArchitectureService[] };
  snapshot: DesignSnapshot;
  saved_at: string;
}

export interface SettingChange {
  service: string;
  type: string;
  field: string; // config field, or usage.<field>
  a: unknown;
  b: unknown;
}

export interface Comparison {
  A: SavedDesign | null;
  B: SavedDesign | null;
  diff: {
    only_in_a: { name: string; type: string }[];
    only_in_b: { name: string; type: string }[];
    changed_settings: SettingChange[];
    identical: boolean;
  } | null;
  highlights: {
    cheaper: { slot: Slot | "tie" | null; difference_usd: number | null; reason: string };
    fewer_risks: { slot: Slot | "tie"; reason: string };
  } | null;
}
