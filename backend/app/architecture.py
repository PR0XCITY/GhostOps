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
