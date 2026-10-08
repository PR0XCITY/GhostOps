"use client";

import { Trash } from "@phosphor-icons/react";
import type { CatalogField, CatalogService } from "@/lib/types";
import type { BuilderService } from "@/lib/builder";

const inputCls =
  "w-full rounded-md border border-line-strong bg-canvas px-2.5 py-1.5 text-sm text-zinc-100 transition-colors duration-150 placeholder:text-zinc-500 focus-visible:border-cyan-400 aria-[invalid=true]:border-red-500/70";

function Toggle({ id, checked, onChange, label }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-9 shrink-0 rounded-full border transition-colors duration-150 ${
        checked ? "border-cyan-400/70 bg-cyan-400/80" : "border-line-strong bg-raised"
      }`}
    >
      <span
        aria-hidden="true"
        className={`absolute left-0 top-0.5 h-3.5 w-3.5 rounded-full bg-zinc-100 transition-transform duration-150 ${
          checked ? "translate-x-[18px]" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

export function FieldInput({ id, field, value, onChange, error }: {
  id: string; field: CatalogField; value: unknown; onChange: (v: unknown) => void; error?: string;
}) {
  const describedBy = [field.help ? `${id}-help` : "", error ? `${id}-err` : ""].filter(Boolean).join(" ") || undefined;
  const common = { id, name: field.name, "aria-invalid": Boolean(error), "aria-describedby": describedBy };

  let control: React.ReactNode;
  if (field.kind === "bool") {
    control = <Toggle id={id} checked={Boolean(value)} onChange={onChange} label={field.label} />;
  } else if (field.kind === "select") {
    control = (
      <select {...common} value={String(value)} className={`${inputCls} bg-canvas`}
              onChange={(e) => onChange(typeof field.default === "number" ? Number(e.target.value) : e.target.value)}>
        {field.options?.map((o) => <option key={String(o)} value={String(o)}>{String(o)}</option>)}
      </select>
    );
  } else if (field.kind === "int") {
    control = (
      <input {...common} type="number" inputMode="numeric" min={field.min} max={field.max} step={1}
             value={value === null || value === undefined ? "" : String(value)}
             placeholder={value === null ? "auto" : undefined}
             onChange={(e) => onChange(e.target.value === "" ? (field.default === null ? null : field.min ?? 0)
                                                               : Math.trunc(Number(e.target.value)))}
             className={`${inputCls} font-mono tabular-nums`} />
    );
  } else if (field.kind === "list") {
    control = (
      <input {...common} type="text" spellCheck={false} autoComplete="off" value={(value as string[] | undefined)?.join(", ") ?? ""}
             onChange={(e) => onChange(e.target.value.split(",").map((v) => v.trim()).filter(Boolean))}
             className={`${inputCls} font-mono`} translate="no" />
    );
  } else {
    control = (
      <input {...common} type="text" spellCheck={false} autoComplete="off" value={String(value ?? "")}
             onChange={(e) => onChange(e.target.value)}
             className={`${inputCls} ${field.kind === "cidr" || field.name === "name" ? "font-mono" : ""}`} translate="no" />
    );
  }

  return (
    <div className={`flex min-w-0 gap-1.5 ${field.kind === "bool" ? "flex-row-reverse items-center justify-end" : "flex-col"}`}>
      <label htmlFor={id} className="text-xs text-zinc-400">{field.label}</label>
      {control}
      {field.help && field.kind !== "bool" && <p id={`${id}-help`} className="text-[11px] leading-snug text-zinc-500">{field.help}</p>}
      {error && <p id={`${id}-err`} role="alert" className="basis-full text-[11px] text-red-300">{error}</p>}
    </div>
  );
}

export function ServiceCard({ service, entry, errors, flagged, onChange, onRemove }: {
  service: BuilderService;
  entry: CatalogService;
  errors: Record<string, string>; // field (or "usage.x") -> message
  flagged: boolean;
  onChange: (next: BuilderService) => void;
  onRemove: () => void;
}) {
  const fields = entry.fields.filter((f) => f.name !== "name");
  const nameField = entry.fields.find((f) => f.name === "name")!;
  const prefix = `svc-${service.id}`;
  return (
    <section
      aria-label={`${entry.label} ${String(service.config.name)}`}
      className={`min-w-0 rounded-md border bg-surface ${flagged ? "border-red-500/60" : "border-line"}`}
    >
      <header className="flex items-center gap-3 border-b border-line px-3 py-2">
        <span className="text-sm font-medium text-zinc-200">{entry.label}</span>
        {!entry.shadow_supported && (
          <span className="rounded border border-amber-300/30 px-1 font-mono text-[10px] text-amber-200">static only</span>
        )}
        {flagged && <span className="rounded border border-red-500/50 bg-red-500/15 px-1 font-mono text-[10px] text-red-200">flagged</span>}
        <button type="button" onClick={onRemove} aria-label={`Remove ${String(service.config.name)}`}
                className="ml-auto rounded-md p-1 text-zinc-500 transition-colors duration-150 hover:bg-raised hover:text-red-300">
          <Trash size={15} aria-hidden="true" />
        </button>
      </header>
      <div className="grid gap-3 px-3 py-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <FieldInput id={`${prefix}-name`} field={{ ...nameField, help: undefined }} value={service.config.name}
                      error={errors.name}
                      onChange={(v) => onChange({ ...service, config: { ...service.config, name: v } })} />
        </div>
        {fields.map((f) => (
          <FieldInput key={f.name} id={`${prefix}-${f.name}`} field={f} value={service.config[f.name]} error={errors[f.name]}
                      onChange={(v) => onChange({ ...service, config: { ...service.config, [f.name]: v } })} />
        ))}
      </div>
      {entry.usage_fields?.length ? (
        <div className="border-t border-line px-3 py-3">
          <p className="mb-2 text-xs text-zinc-400">Monthly usage (priced by Infracost)</p>
          <div className="grid gap-3 sm:grid-cols-2">
            {entry.usage_fields.map((f) => (
              <FieldInput key={f.name} id={`${prefix}-usage-${f.name}`} field={f} value={service.usage[f.name]}
                          error={errors[`usage.${f.name}`]}
                          onChange={(v) => onChange({ ...service, usage: { ...service.usage, [f.name]: v } })} />
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
