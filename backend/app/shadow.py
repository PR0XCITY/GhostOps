"""Shadow execution: apply a Terraform configuration to MiniStack, never to AWS.

run_shadow(dir) does, under a process-wide lock (MiniStack is shared):
  1. copy the configuration to a temp workspace (no .terraform/, state or plan files),
  2. add ghostops_shadow_override.tf, which forces the default aws provider to
     MiniStack with fake keys and a local backend (Terraform override-file merge),
  3. reset MiniStack (POST /_ministack/reset) so the run starts from empty,
  4. terraform init -> plan -> apply, then read the resulting state and list what
     really exists in MiniStack with boto3 (inventory(): independent of the state),
  5. reset MiniStack again and delete the workspace, whatever happened.

Credential safety, in depth: besides the override, Terraform runs with every
AWS_* variable removed, AWS_ACCESS_KEY_ID/SECRET=test, the shared credentials
and config files pointed at empty files, instance metadata disabled and
AWS_ENDPOINT_URL set to MiniStack. A provider block the override misses
(e.g. an aliased provider) therefore still has no real credentials.

A failure at any stage is a result, not an exception: success=False plus a
GO-SHADOW-001 finding (HIGH) per failing resource. Per the design principle it
may be a MiniStack gap rather than a real defect, so it asks for human review.
Environment problems (MiniStack down, terraform missing) raise ShadowError.

CLI: python -m app.shadow <terraform dir>   (prints the result as JSON)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MINISTACK_URL = os.environ.get("MINISTACK_ENDPOINT_URL", "http://localhost:4566").rstrip("/")
REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_CACHE = REPO_ROOT / ".terraform-plugin-cache"
OVERRIDE_FILE = "ghostops_shadow_override.tf"
PLAN_FILE = "shadow.tfplan"

# Every endpoint the default aws provider may need; all go to the MiniStack gateway.
ENDPOINT_SERVICES = (
    "acm", "apigateway", "apigatewayv2", "appsync", "athena", "autoscaling", "cloudformation",
    "cloudfront", "cloudwatch", "codebuild", "cognitoidentity", "cognitoidp", "dynamodb", "ec2",
    "ecr", "ecs", "efs", "eks", "elasticache", "elb", "elbv2", "emr", "events", "firehose", "glue",
    "iam", "kafka", "kinesis", "kms", "lambda", "logs", "organizations", "rds", "route53", "s3",
    "s3control", "scheduler", "secretsmanager", "ses", "sesv2", "sfn", "sns", "sqs", "ssm", "sts",
    "wafv2",
)

_lock = threading.Lock()


class ShadowError(RuntimeError):
    """The shadow environment itself is unusable (not a verdict on the plan)."""


@dataclass
class ShadowResult:
    success: bool
    stage: str  # "complete", or the stage that failed: "init" | "plan" | "apply"
    resources: list[dict[str, Any]] = field(default_factory=list)  # from Terraform state
    # What boto3 actually found in MiniStack after the apply, before teardown.
    inventory: list[dict[str, Any]] = field(default_factory=list)
    inventory_error: str | None = None
    planned_changes: int = 0
    error: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- MiniStack --------------------------------------------------------------------


def _ministack(path: str, method: str = "GET", timeout: float = 10) -> dict[str, Any]:
    req = urllib.request.Request(f"{MINISTACK_URL}{path}", method=method, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise ShadowError(
            f"MiniStack not reachable at {MINISTACK_URL} ({exc}). Start it: docker compose up -d"
        ) from None
    try:
        return json.loads(body) if body else {}
    except ValueError:
        return {}


def _client(service: str):
    import boto3  # backend dependency; imported lazily so the module loads without it

    return boto3.client(service, endpoint_url=MINISTACK_URL, region_name="us-east-1",
                        aws_access_key_id="test", aws_secret_access_key="test")


def _pages(client, op: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    if client.can_paginate(op):
        return [item for page in client.get_paginator(op).paginate(**kwargs) for item in page.get(key, [])]
    return getattr(client, op)(**kwargs).get(key, [])


def inventory() -> tuple[list[dict[str, Any]], str | None]:
    """Resources that exist in MiniStack, found with boto3 (independent of Terraform state).

    Each item is {"type": <Terraform resource type>, "id": <AWS id/name/ARN>}. MiniStack's
    built-in defaults (default VPC, its subnets/security group/gateway) are excluded, and
    the shadow run resets MiniStack first, so everything listed was created by this run.
    Errors in one service do not hide the others; they are joined into the second value.
    """
    found: list[dict[str, Any]] = []
    errors: list[str] = []

    def collect(service: str, fn) -> None:
        try:
            found.extend(fn(_client(service)))
        except Exception as exc:  # report, don't hide the other services
            errors.append(f"{service}: {type(exc).__name__}: {str(exc)[:160]}")

    def ec2(c):
        vpcs = _pages(c, "describe_vpcs", "Vpcs")
        default_vpcs = {v["VpcId"] for v in vpcs if v.get("IsDefault")}
        out = [{"type": "aws_vpc", "id": v["VpcId"]} for v in vpcs if not v.get("IsDefault")]
        out += [{"type": "aws_subnet", "id": s["SubnetId"]} for s in _pages(c, "describe_subnets", "Subnets")
                if s.get("VpcId") not in default_vpcs and not s.get("DefaultForAz")]
        out += [{"type": "aws_security_group", "id": g["GroupId"]}
                for g in _pages(c, "describe_security_groups", "SecurityGroups") if g.get("GroupName") != "default"]
        out += [{"type": "aws_internet_gateway", "id": g["InternetGatewayId"]}
                for g in _pages(c, "describe_internet_gateways", "InternetGateways")
                if not {a.get("VpcId") for a in g.get("Attachments", [])} & default_vpcs]
        out += [{"type": "aws_instance", "id": i["InstanceId"]}
                for r in _pages(c, "describe_instances", "Reservations") for i in r.get("Instances", [])
                if i.get("State", {}).get("Name") not in ("terminated", "shutting-down")]
        out += [{"type": "aws_ebs_volume", "id": v["VolumeId"]} for v in _pages(c, "describe_volumes", "Volumes")]
        return out

    def elbv2(c):
        lbs = _pages(c, "describe_load_balancers", "LoadBalancers")
        out = [{"type": "aws_lb", "id": lb["LoadBalancerArn"]} for lb in lbs]
        out += [{"type": "aws_lb_target_group", "id": t["TargetGroupArn"]}
                for t in _pages(c, "describe_target_groups", "TargetGroups")]
        for lb in lbs:
            out += [{"type": "aws_lb_listener", "id": li["ListenerArn"]}
                    for li in _pages(c, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"])]
        return out

    def iam(c):
        out = [{"type": "aws_iam_role", "id": r["RoleName"]} for r in _pages(c, "list_roles", "Roles")
               if not r.get("Path", "/").startswith("/aws-service-role/")]
        out += [{"type": "aws_iam_policy", "id": p["Arn"]} for p in _pages(c, "list_policies", "Policies", Scope="Local")]
        return out

    collect("ec2", ec2)
    collect("s3", lambda c: [{"type": "aws_s3_bucket", "id": b["Name"]} for b in c.list_buckets().get("Buckets", [])])
    # id = DbiResourceId, the same id Terraform's state uses for aws_db_instance; name = identifier
    collect("rds", lambda c: [{"type": "aws_db_instance", "id": d.get("DbiResourceId") or d["DBInstanceIdentifier"],
                               "name": d["DBInstanceIdentifier"]}
                              for d in _pages(c, "describe_db_instances", "DBInstances")])
    collect("iam", iam)
    collect("lambda", lambda c: [{"type": "aws_lambda_function", "id": f["FunctionName"]}
                                 for f in _pages(c, "list_functions", "Functions")])
    collect("dynamodb", lambda c: [{"type": "aws_dynamodb_table", "id": t} for t in _pages(c, "list_tables", "TableNames")])
    collect("cloudwatch", lambda c: [{"type": "aws_cloudwatch_metric_alarm", "id": a["AlarmName"]}
                                     for a in _pages(c, "describe_alarms", "MetricAlarms")])
    collect("elbv2", elbv2)
    return sorted(found, key=lambda r: (r["type"], r["id"])), "; ".join(errors) or None


def ministack_version() -> str:
    return str(_ministack("/_ministack/health").get("version", "unknown"))


def reset_ministack() -> None:
    _ministack("/_ministack/reset", method="POST", timeout=60)


# --- Terraform workspace ------------------------------------------------------------


def override_hcl(endpoint: str = MINISTACK_URL) -> str:
    endpoints = "\n".join(f'    {svc:<15} = "{endpoint}"' for svc in ENDPOINT_SERVICES)
    return f"""# Generated by GhostOps shadow execution. Forces the run onto MiniStack.
terraform {{
  backend "local" {{}}
}}

provider "aws" {{
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {{
{endpoints}
  }}
}}
"""


def shadow_env(workspace: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("AWS_")}
    empty = workspace / "empty-aws-file"
    empty.write_text("", encoding="utf-8")
    env.update(
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
        AWS_DEFAULT_REGION="us-east-1",
        AWS_REGION="us-east-1",
        AWS_SHARED_CREDENTIALS_FILE=str(empty),
        AWS_CONFIG_FILE=str(empty),
        AWS_EC2_METADATA_DISABLED="true",
        AWS_ENDPOINT_URL=MINISTACK_URL,
        TF_IN_AUTOMATION="1",
        TF_INPUT="0",
        TF_PLUGIN_CACHE_DIR=str(PLUGIN_CACHE),
        # Generated configs (app/generator.py) ship without a lock file; without this,
        # Terraform skips the cache and re-downloads the ~685 MB AWS provider per run.
        TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE="1",
    )
    return env


def _prepare_workspace(source: Path, workspace: Path) -> Path:
    work = workspace / "config"
    shutil.copytree(
        source,
        work,
        ignore=shutil.ignore_patterns(".terraform", "terraform.tfstate.d", "*.tfstate", "*.tfstate.*",
                                      "*.tfplan", OVERRIDE_FILE),
    )
    (work / OVERRIDE_FILE).write_text(override_hcl(), encoding="utf-8")
    return work


def _tail(text: str, lines: int = 40) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


_ERROR_ADDRESS = re.compile(r"^\s*with ((?:module\.[\w-]+(?:\[[^\]]*\])?\.)*[\w-]+\.[\w-]+(?:\[[^\]]*\])?),", re.M)


def failure_findings(stage: str, error: str) -> list[dict[str, Any]]:
    """One GO-SHADOW-001 finding per resource named in Terraform's error output."""
    first_error = next((l.strip() for l in error.splitlines() if l.strip().startswith("Error:")), "")
    detail = first_error.removeprefix("Error:").strip() or f"terraform {stage} failed"
    addresses = list(dict.fromkeys(_ERROR_ADDRESS.findall(error))) or [f"(terraform {stage})"]
    return [
        {
            "rule_id": "GO-SHADOW-001",
            "severity": "HIGH",
            "address": address,
            "message": (
                f"Shadow {stage} on MiniStack failed for {address}: {detail}. The change could not be "
                "verified; this may be a real defect or a MiniStack limitation, so a human must review it."
            ),
        }
        for address in addresses
    ]


def _state_resources(state: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def visit(module: dict[str, Any]) -> None:
        for res in module.get("resources", []) or []:
            if res.get("mode", "managed") != "managed":
                continue
            values = res.get("values") or {}
            out.append({"address": res["address"], "type": res["type"], "id": values.get("id")})
        for child in module.get("child_modules", []) or []:
            visit(child)

    visit((state.get("values") or {}).get("root_module") or {})
    return sorted(out, key=lambda r: r["address"])


def run_shadow(source_dir: str | Path, *, timeout: float = 900) -> ShadowResult:
    source = Path(source_dir).resolve()
    if not source.is_dir() or not any(source.glob("*.tf")):
        raise ShadowError(f"{source} is not a Terraform configuration directory (no *.tf files)")
    terraform = shutil.which("terraform")
    if not terraform:
        raise ShadowError("terraform not found on PATH")
    PLUGIN_CACHE.mkdir(exist_ok=True)

    with _lock:
        ministack_version()  # fail fast if MiniStack is down
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="ghostops-shadow-") as tmp:
            workspace = Path(tmp)
            work = _prepare_workspace(source, workspace)
            env = shadow_env(workspace)

            def tf(stage: str, *args: str) -> subprocess.CompletedProcess[str] | ShadowResult:
                try:
                    proc = subprocess.run(
                        [terraform, *args], cwd=work, env=env, capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=timeout,
                    )
                except subprocess.TimeoutExpired:
                    error = f"terraform {stage} timed out after {timeout}s"
                    return ShadowResult(False, stage, error=error, findings=failure_findings(stage, error))
                if proc.returncode != 0:
                    error = _tail(proc.stderr or proc.stdout)
                    return ShadowResult(False, stage, error=error, findings=failure_findings(stage, error))
                return proc

            reset_ministack()
            try:
                result = _run_stages(tf)
            finally:
                reset_ministack()
        result.duration_s = round(time.monotonic() - started, 1)
        return result


def _run_stages(tf) -> ShadowResult:
    step = tf("init", "init", "-input=false", "-no-color")
    if isinstance(step, ShadowResult):
        return step
    step = tf("plan", "plan", "-input=false", "-no-color", f"-out={PLAN_FILE}")
    if isinstance(step, ShadowResult):
        return step
    shown = tf("plan", "show", "-json", "-no-color", PLAN_FILE)
    if isinstance(shown, ShadowResult):
        return shown
    planned = sum(
        1 for rc in json.loads(shown.stdout).get("resource_changes", [])
        if rc.get("mode") == "managed" and rc["change"]["actions"] != ["no-op"]
    )

    applied = tf("apply", "apply", "-input=false", "-no-color", "-auto-approve", PLAN_FILE)
    state = tf("apply", "show", "-json", "-no-color")  # also after a failed apply: partial state
    resources = _state_resources(json.loads(state.stdout)) if not isinstance(state, ShadowResult) else []
    found, inventory_error = inventory()  # what MiniStack really holds, before the reset
    if isinstance(applied, ShadowResult):
        applied.resources, applied.planned_changes = resources, planned
        applied.inventory, applied.inventory_error = found, inventory_error
        return applied
    return ShadowResult(True, "complete", resources=resources, planned_changes=planned,
                        inventory=found, inventory_error=inventory_error)


def plan_json(source_dir: str | Path, *, timeout: float = 600) -> dict[str, Any]:
    """`terraform show -json` of a fresh plan for source_dir, made in a scrubbed temp workspace.

    Uses the same MiniStack override and credential-free environment as the shadow run;
    a create-only plan does not need MiniStack itself. Raises ShadowError on failure.
    """
    source = Path(source_dir).resolve()
    terraform = shutil.which("terraform")
    if not terraform:
        raise ShadowError("terraform not found on PATH")
    PLUGIN_CACHE.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ghostops-plan-") as tmp:
        work = _prepare_workspace(source, Path(tmp))
        env = shadow_env(Path(tmp))
        for args in (["init", "-input=false"], ["plan", "-input=false", f"-out={PLAN_FILE}"], ["show", "-json", PLAN_FILE]):
            proc = subprocess.run([terraform, *args, "-no-color"], cwd=work, env=env, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout)
            if proc.returncode != 0:
                raise ShadowError(f"terraform {args[0]} failed: {_tail(proc.stderr or proc.stdout, 15)}")
        return json.loads(proc.stdout)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m app.shadow <terraform dir>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(run_shadow(sys.argv[1]).to_dict(), indent=2))
