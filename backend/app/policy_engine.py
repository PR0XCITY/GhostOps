"""Evaluate the OPA/Rego policies in backend/rules against a Terraform plan.

How it works: the plan JSON (from `terraform show -json`) is validated with the
plan parser, then piped to the `opa` binary:

    opa eval --format json --stdin-input --data backend/rules data.ghostops.result

which returns {"deny": [...], "warn": [...]}. Every finding has rule_id,
severity, address and message. The same evaluation by hand, from backend/:

    opa eval --format pretty --data rules --input tests/fixtures/bad_plan.json data.ghostops.result

The opa binary is found via GHOSTOPS_OPA_BIN, then PATH, then (Windows) the
current PATH from the registry, for shells started before OPA was installed. Any OPA failure raises PolicyEngineError: a gate that cannot evaluate
its policies must not report "no findings".

CLI: python -m app.policy_engine <plan.json>   (exit 1 if any deny finding)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.plan_parser import PlanParseError, parse_plan

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
QUERY = "data.ghostops.result"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

Decision = Literal["deny", "warn"]


class PolicyEngineError(RuntimeError):
    """OPA could not be run or returned something we cannot trust."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    address: str
    message: str
    decision: Decision


def _registry_path() -> str | None:
    """Current machine + user PATH from the Windows registry (None elsewhere)."""
    if sys.platform != "win32":
        return None
    import winreg

    parts = []
    for root, key in (
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        (winreg.HKEY_CURRENT_USER, "Environment"),
    ):
        try:
            with winreg.OpenKey(root, key) as handle:
                value, _ = winreg.QueryValueEx(handle, "Path")
        except OSError:
            continue
        parts.append(os.path.expandvars(value))
    return os.pathsep.join(parts) or None


def find_opa() -> str:
    configured = os.environ.get("GHOSTOPS_OPA_BIN")
    if configured:
        if not Path(configured).is_file():
            raise PolicyEngineError(f"GHOSTOPS_OPA_BIN points to a missing file: {configured}")
        return configured
    on_path = shutil.which("opa")
    if on_path:
        return on_path
    # A process started before OPA was installed has a stale PATH; the registry
    # has the current one (what a fresh terminal would get).
    fresh = _registry_path()
    on_fresh_path = shutil.which("opa", path=fresh) if fresh else None
    if on_fresh_path:
        return on_fresh_path
    raise PolicyEngineError(
        "opa binary not found. Install it (winget install --id open-policy-agent.opa -e) "
        "or set GHOSTOPS_OPA_BIN to its full path."
    )


def _to_finding(raw: Any, decision: Decision) -> Finding:
    if not isinstance(raw, dict):
        raise PolicyEngineError(f"malformed {decision} finding from OPA: {raw!r}")
    try:
        finding = Finding(
            rule_id=str(raw["rule_id"]),
            severity=str(raw["severity"]),
            address=str(raw["address"]),
            message=str(raw["message"]),
            decision=decision,
        )
    except KeyError as exc:
        raise PolicyEngineError(f"{decision} finding missing field {exc}: {raw!r}") from None
    if finding.severity not in SEVERITY_ORDER:
        raise PolicyEngineError(f"unknown severity {finding.severity!r} in {finding.rule_id}")
    return finding


def evaluate(plan: dict[str, Any], *, rules_dir: Path = RULES_DIR, timeout: float = 30) -> list[Finding]:
    """Return all findings for `plan`, most severe first."""
    parse_plan(plan)  # rejects malformed plans and unknown actions before OPA sees them
    cmd = [find_opa(), "eval", "--format", "json", "--stdin-input", "--data", str(rules_dir), QUERY]
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(plan),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise PolicyEngineError(f"opa eval timed out after {timeout}s") from None
    if proc.returncode != 0:
        raise PolicyEngineError(f"opa eval failed (exit {proc.returncode}): {proc.stderr.strip()}")

    try:
        value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        raise PolicyEngineError(
            f"opa returned no value for {QUERY}; are the rules in {rules_dir} loaded? "
            f"stdout={proc.stdout.strip()[:200]!r}"
        ) from None
    if not isinstance(value, dict) or not isinstance(value.get("deny"), list) or not isinstance(value.get("warn"), list):
        raise PolicyEngineError(f"{QUERY} must be {{deny: [...], warn: [...]}}, got {value!r}")

    findings = [_to_finding(f, "deny") for f in value["deny"]]
    findings += [_to_finding(f, "warn") for f in value["warn"]]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.address, f.message))
    return findings


def evaluate_file(path: str | Path, **kwargs: Any) -> list[Finding]:
    try:
        # bytes, so UTF-16 from a PowerShell `>` redirect is detected too
        plan = json.loads(Path(path).read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanParseError(f"invalid JSON: {exc}") from None
    return evaluate(plan, **kwargs)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.policy_engine <plan.json>", file=sys.stderr)
        return 2
    findings = evaluate_file(argv[1])
    for f in findings:
        print(f"{f.decision.upper():4} {f.severity:8} {f.rule_id:10} {f.message}")
    if not findings:
        print("no findings")
    return 1 if any(f.decision == "deny" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
