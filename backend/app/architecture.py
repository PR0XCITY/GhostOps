"""Analyse a catalog architecture end to end.

    analyze_architecture({"services": [{"type": "ec2", "config": {...}},
                                       {"type": "s3", "config": {...}, "usage": {...}}]})

1. generate Terraform from the catalog (app/generator.py; invalid input raises
   ArchitectureError before anything runs),
2. `terraform plan` it in a scrubbed temp workspace -> plan JSON,
3. shadow-apply only the shadow_supported services on MiniStack (static_only
   services are still in the plan, so every static check covers them),
4. run the existing certificate pipeline on the plan: OPA, graph diff, shadow
   result + boto3 inventory, Infracost with the architecture's usage inputs,
   remediations, explanation, signature.

If no service can be shadow-applied, the shadow run is reported as not run and the
verdict stays fail-closed (BLOCKED_PENDING_REVIEW), with the reason in shadow_run.error.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from app.certificate import build_certificate
from app.generator import generate
from app.shadow import ShadowResult, plan_json, run_shadow


def analyze_architecture(
    architecture: dict[str, Any],
    *,
    use_groq: bool = True,
    planner: Callable[[str], dict[str, Any]] = plan_json,
    shadow_runner: Callable[[str], ShadowResult] = run_shadow,
    **certificate_kwargs: Any,
) -> dict[str, Any]:
    generated = generate(architecture)  # ArchitectureError on invalid input
    with tempfile.TemporaryDirectory(prefix="ghostops-arch-") as tmp:
        full_dir = Path(tmp, "full")
        generated.write(full_dir)
        plan = planner(str(full_dir))

        subset = generated.shadow_subset()
        if subset is None:
            static = ", ".join(s.slug for s in generated.services)
            shadow = ShadowResult(False, "skipped", error=(
                f"Shadow run not performed: no service in this architecture is shadow_supported ({static}); "
                "they were checked by static analysis only."), findings=[{
                    "rule_id": "GO-SHADOW-001", "severity": "HIGH", "address": "(shadow run)",
                    "message": "No service could be applied on MiniStack, so the change is unverified."}])
        else:
            shadow_dir = Path(tmp, "shadow")
            subset.write(shadow_dir)
            shadow = shadow_runner(str(shadow_dir))

        return build_certificate(plan, shadow_result=shadow, use_groq=use_groq, generated=generated,
                                 **certificate_kwargs)


def services_with_resources(generated) -> list[dict[str, Any]]:
    """Each service with the resource addresses it generated (for diagrams and per-service cost)."""
    owned: dict[str, list[str]] = {}
    for address, service in generated.owners.items():
        owned.setdefault(service.slug, []).append(address)
    return [{"type": s.type, "name": s.slug, "shadow_supported": s.shadow_supported, "config": s.config,
             "usage": s.usage, "resources": owned.get(s.slug, [])} for s in generated.services]


def check_architecture(
    architecture: dict[str, Any],
    *,
    planner: Callable[[str], dict[str, Any]] = plan_json,
    cost_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fast static check for the builder: plan + OPA + graph + cost + fixes, no shadow apply.

    Not a certificate: nothing is signed or stored, and verdict_preview only says what
    the static checks alone would decide (a full analysis also needs the MiniStack apply).
    Remediation text is the template (no Groq call per keystroke).
    """
    from app.blast_radius import analyze as analyze_blast_radius
    from app.certificate import BLOCKING, SEVERITY_ORDER, cost_section, graph_flags, policy_flags
    from app.plan_parser import parse_plan
    from app.remediation import remediate

    started = time.monotonic()
    generated = generate(architecture)
    with tempfile.TemporaryDirectory(prefix="ghostops-check-") as tmp:
        generated.write(tmp)
        plan = planner(tmp)
    changes = parse_plan(plan)
    blast = analyze_blast_radius(plan)
    flags = policy_flags(plan) + graph_flags(blast)
    flags.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["rule"], f["resource"], f["message"]))
    for f, remediation in zip(flags, remediate(flags, generated, use_groq=False)):
        f["remediation"] = remediation
    cost, breakdown = cost_section(plan, cost_result, generated=generated)
    return {
        "verdict_preview": "BLOCKED_PENDING_REVIEW" if any(f["severity"] in BLOCKING for f in flags) else "AUTO_APPROVED",
        "static_only": True,
        "risk_flags": flags,
        "newly_public": blast["newly_public"],
        "iam_widened": blast["iam_widened"],
        "graph": blast["graph"],
        "cost_delta": cost,
        "cost_breakdown": breakdown,
        "resource_count": len(changes),
        "services": services_with_resources(generated),
        "generated_terraform": generated.main_tf,
        "duration_s": round(time.monotonic() - started, 1),
    }
