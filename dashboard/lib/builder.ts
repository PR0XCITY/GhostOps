// Architecture Builder state helpers (pure functions, no React).

import type {
  ArchitectureService, ArchitectureServiceInfo, CatalogService, ConfigChange, CostBreakdownRow,
} from "./types";

export interface BuilderService {
  id: string; // client-side key only
  type: string;
  config: Record<string, unknown>;
  usage: Record<string, unknown>;
}

let counter = 0;
const newId = () => `svc-${Date.now().toString(36)}-${(counter++).toString(36)}`;

export function uniqueName(type: string, taken: Set<string>): string {
  const base = type.replace(/_/g, "-");
  for (let n = 1; ; n++) {
    const name = `${base}-${n}`;
    if (!taken.has(name)) return name;
  }
}

export function newService(entry: CatalogService, taken: Set<string>, overrides: Partial<BuilderService> = {}): BuilderService {
  const config: Record<string, unknown> = Object.fromEntries(entry.fields.map((f) => [f.name, structuredClone(f.default)]));
  config.name = uniqueName(entry.type, taken);
  const usage: Record<string, unknown> = Object.fromEntries((entry.usage_fields ?? []).map((f) => [f.name, f.default]));
  return {
    id: newId(),
    type: entry.type,
    config: { ...config, ...(overrides.config ?? {}) },
    usage: { ...usage, ...(overrides.usage ?? {}) },
  };
}

/** The JSON the API takes. null usage values (e.g. S3 storage = bucket size) are left to the backend default. */
export function toArchitecture(services: BuilderService[]): { services: ArchitectureService[] } {
  return {
    services: services.map((s) => {
      const usage = Object.fromEntries(Object.entries(s.usage).filter(([, v]) => v !== null && v !== ""));
      return Object.keys(usage).length ? { type: s.type, config: s.config, usage } : { type: s.type, config: s.config };
    }),
  };
}

/** Apply a fix's catalog config changes to the matching services (by name). Returns null if nothing applies. */
export function applyChanges(services: BuilderService[], changes: ConfigChange[]): BuilderService[] | null {
  let applied = false;
  const next = services.map((s) => {
    const mine = changes.filter((c) => c.service && c.field && c.service === s.config.name && c.type === s.type);
    if (!mine.length) return s;
    applied = true;
    return { ...s, config: { ...s.config, ...Object.fromEntries(mine.map((c) => [c.field as string, c.to])) } };
  });
  return applied ? next : null;
}

export function canApply(services: BuilderService[], changes: ConfigChange[]): boolean {
  return changes.some((c) => c.service && c.field && services.some((s) => s.config.name === c.service && s.type === c.type));
}

/** resource address (without [index]) -> service name, from the preview/check `services` list. */
export function ownerMap(services: ArchitectureServiceInfo[] | undefined): Map<string, string> {
  const map = new Map<string, string>();
  for (const s of services ?? []) for (const address of s.resources ?? []) map.set(address, s.name);
  return map;
}

export const stripIndex = (address: string) => address.replace(/\[[^\]]*\]/g, "");

export interface ServiceCost {
  name: string;
  type: string;
  monthly_usd: number | null; // null when no resource of the service could be priced
  partial: boolean; // some resources unpriced
  usageBased: boolean;
}

export function costByService(rows: CostBreakdownRow[], owners: Map<string, string>,
                              services: ArchitectureServiceInfo[]): ServiceCost[] {
  return services.map((s) => {
    const mine = rows.filter((r) => owners.get(stripIndex(r.resource)) === s.name);
    const priced = mine.filter((r) => r.monthly_usd !== null);
    return {
      name: s.name,
      type: s.type,
      monthly_usd: priced.length ? priced.reduce((sum, r) => sum + (r.monthly_usd ?? 0), 0) : null,
      partial: priced.length > 0 && priced.length < mine.length,
      usageBased: mine.some((r) => (r.note ?? "").includes("zero usage") && !Object.keys(r.usage_assumptions ?? {}).length),
    };
  });
}

/** Builder versions of the two original demos. */
export const EXAMPLES: Record<"risky" | "safe", { label: string; services: Omit<ArchitectureService, "usage">[] }> = {
  risky: {
    label: "Risky (like demo/bad)",
    services: [
      { type: "ec2", config: { name: "web", ssh_source_cidr: "0.0.0.0/0" } },
      { type: "iam", config: { name: "admin-star", actions: ["*"], resource: "*" } },
      { type: "s3", config: { name: "public-bucket", public_access: true } },
      { type: "rds", config: { name: "unencrypted-db", encrypted: false } },
    ],
  },
  safe: {
    label: "Safe (like demo/good)",
    services: [
      { type: "s3", config: { name: "logs", size_gb: 20 } },
      { type: "cloudwatch_alarm", config: { name: "web-cpu" } },
    ],
  },
};

export function loadExample(name: "risky" | "safe", catalog: CatalogService[]): BuilderService[] {
  const taken = new Set<string>();
  return EXAMPLES[name].services.map((spec) => {
    const entry = catalog.find((c) => c.type === spec.type);
    if (!entry) throw new Error(`catalog has no ${spec.type}`);
    const s = newService(entry, taken, { config: spec.config });
    taken.add(String(s.config.name));
    return s;
  });
}
