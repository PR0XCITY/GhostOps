"""Generate Terraform plan JSON fixtures for backend tests.

Runs real `terraform plan` + `terraform show -json` against MiniStack and writes
the results to backend/tests/fixtures/:

  bad_plan.json           demo/bad, fresh: everything is a create
  good_plan.json          demo/good, fresh: everything is a create
  good_noop_plan.json     demo/good applied, then re-planned unchanged:
                          bucket is a no-op
  good_modified_plan.json demo/good applied, then environment=prod:
                          bucket is an in-place update (tag change)
  good_destroy_plan.json  demo/good applied, then -destroy: everything is a delete

Known MiniStack gap: alarms created through the Terraform AWS provider read back
without description/dimensions/period/statistic/tags, so after apply the alarm
always shows as an `update` (listed under `resource_drift`). The fixtures keep
this real behaviour; boto3 round-trips the same fields correctly.

demo/good is applied to MiniStack temporarily and destroyed again at the end.
demo/bad is only planned, never applied.

Requires MiniStack running (docker compose up -d). Usage, from the repo root:
  .venv\\Scripts\\python.exe demo\\generate_fixtures.py
"""

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "backend" / "tests" / "fixtures"
PLUGIN_CACHE = ROOT / ".terraform-plugin-cache"
HEALTH_URL = "http://localhost:4566/_ministack/health"


def tf_env():
    # Belt and braces: the configs hard-code fake keys, but also make sure no real
    # AWS profile or credentials from the user's environment can leak in.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update(
        AWS_ACCESS_KEY_ID="test",
        AWS_SECRET_ACCESS_KEY="test",
        AWS_DEFAULT_REGION="us-east-1",
        TF_IN_AUTOMATION="1",
        # Share one copy of the ~685 MB AWS provider across all demo dirs.
        TF_PLUGIN_CACHE_DIR=str(PLUGIN_CACHE),
    )
    return env


def tf(workdir: Path, *args: str) -> str:
    cmd = ["terraform", *args]
    print(f"[{workdir.name}] {' '.join(cmd)}", flush=True)
    result = subprocess.run(
        cmd, cwd=workdir, env=tf_env(), capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"terraform {args[0]} failed in {workdir} (exit {result.returncode})")
    return result.stdout


def plan_to_fixture(workdir: Path, name: str, *plan_args: str) -> None:
    planfile = f"{name}.tfplan"
    tf(workdir, "plan", "-input=false", "-no-color", f"-out={planfile}", *plan_args)
    plan = json.loads(tf(workdir, "show", "-no-color", "-json", planfile))
    out = FIXTURES / f"{name}.json"
    out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n")
    (workdir / planfile).unlink()
    actions = [rc["change"]["actions"] for rc in plan.get("resource_changes", [])]
    print(f"  -> {out.relative_to(ROOT)}  actions={actions}", flush=True)


def main() -> None:
    try:
        urllib.request.urlopen(HEALTH_URL, timeout=5)
    except OSError as exc:
        raise SystemExit(f"MiniStack not reachable at {HEALTH_URL} ({exc}). Run: docker compose up -d")

    FIXTURES.mkdir(parents=True, exist_ok=True)
    PLUGIN_CACHE.mkdir(exist_ok=True)
    bad = ROOT / "demo" / "bad"
    good = ROOT / "demo" / "good"

    tf(bad, "init", "-input=false", "-no-color")
    plan_to_fixture(bad, "bad_plan")

    tf(good, "init", "-input=false", "-no-color")
    # Start from an empty MiniStack state so the first plan is all creates.
    tf(good, "destroy", "-auto-approve", "-input=false", "-no-color")
    try:
        plan_to_fixture(good, "good_plan")
        tf(good, "apply", "-auto-approve", "-input=false", "-no-color")
        plan_to_fixture(good, "good_noop_plan")
        plan_to_fixture(good, "good_modified_plan", "-var=environment=prod")
        plan_to_fixture(good, "good_destroy_plan", "-destroy")
    finally:
        tf(good, "destroy", "-auto-approve", "-input=false", "-no-color")


if __name__ == "__main__":
    main()
