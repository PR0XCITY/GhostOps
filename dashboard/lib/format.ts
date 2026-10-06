import type { Severity } from "./types";
import { SEVERITIES } from "./types";

export function formatUsd(value: number | null): string {
  if (value === null) return "n/a";
  const sign = value > 0 ? "+" : value < 0 ? "-" : "";
  return `${sign}$${Math.abs(value).toFixed(2)}`;
}

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function shortHash(hash: string, length = 12): string {
  return hash.length > length ? `${hash.slice(0, length)}` : hash;
}

export function topSeverity(counts: Record<Severity, number>): Severity | null {
  return SEVERITIES.find((s) => counts[s] > 0) ?? null;
}

export function resourceType(address: string): string {
  const parts = address.split(".").map((p) => p.split("[")[0]);
  while (parts.length >= 2 && parts[0] === "module") parts.splice(0, 2);
  return parts[0] ?? address;
}
