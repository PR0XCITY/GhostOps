from pathlib import Path

import boto3
import pytest

from app import shadow
from app.shadow import ShadowError, failure_findings, override_hcl, run_shadow, shadow_env

DEMO = Path(__file__).resolve().parents[2] / "demo"
LOCK_FILE = DEMO / "good" / ".terraform.lock.hcl"


def ministack_up() -> bool:
    try:
        shadow.ministack_version()
        return True
    except ShadowError:
        return False


def integration(test):
    """Real Terraform runs against MiniStack. Part of the slow `integration` set."""
    skip = pytest.mark.skipif(not ministack_up(), reason="MiniStack not running (docker compose up -d)")
    return pytest.mark.integration(skip(test))


def client(service):
    return boto3.client(service, endpoint_url=shadow.MINISTACK_URL, region_name="us-east-1",
                        aws_access_key_id="test", aws_secret_access_key="test")


def assert_ministack_empty():
    assert client("s3").list_buckets()["Buckets"] == []
    assert client("ec2").describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["ghostops-*"]}])["SecurityGroups"] == []
    assert client("iam").list_policies(Scope="Local")["Policies"] == []


def write_config(path: Path, body: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".terraform.lock.hcl").write_bytes(LOCK_FILE.read_bytes())
    (path / "main.tf").write_text(
        'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n  }\n}\n'
        'provider "aws" {\n  region = "us-east-1"\n}\n' + body,
        encoding="utf-8",
    )
    return path


# --- unit: safety ------------------------------------------------------------------


def test_env_scrubs_real_aws_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALREALREALREAL")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "real-token")
    monkeypatch.setenv("AWS_PROFILE", "production")
    env = shadow_env(tmp_path)
    assert env["AWS_ACCESS_KEY_ID"] == "test" and env["AWS_SECRET_ACCESS_KEY"] == "test"
    assert "AWS_SESSION_TOKEN" not in env and "AWS_PROFILE" not in env
    assert Path(env["AWS_SHARED_CREDENTIALS_FILE"]).read_text() == ""
    assert Path(env["AWS_CONFIG_FILE"]).read_text() == ""
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"
    assert env["AWS_ENDPOINT_URL"] == shadow.MINISTACK_URL
    leaked = {"AKIAREALREALREALREAL", "real-secret", "real-token", "production"} & set(env.values())
    assert not leaked


def test_override_points_everything_at_ministack():
    hcl = override_hcl("http://localhost:4566")
    for line in ('access_key                  = "test"', "skip_credentials_validation = true",
                 "skip_requesting_account_id  = true", 'backend "local"'):
        assert line in hcl
    for svc in ("ec2", "iam", "s3", "sts", "rds", "cloudwatch"):
        assert f'    {svc:<15} = "http://localhost:4566"' in hcl
    assert "amazonaws.com" not in hcl


def test_workspace_excludes_state_and_plugins(tmp_path):
    src = tmp_path / "src"
    (src / ".terraform").mkdir(parents=True)
    for name in ("main.tf", "terraform.tfstate", "terraform.tfstate.backup", "old.tfplan", ".terraform.lock.hcl"):
        (src / name).write_text("x", encoding="utf-8")
    work = shadow._prepare_workspace(src, tmp_path / "ws")
    assert sorted(p.name for p in work.iterdir()) == [".terraform.lock.hcl", shadow.OVERRIDE_FILE, "main.tf"]


def test_failure_findings_name_each_failing_resource():
    error = ("Error: creating thing: boom\n\n  with aws_s3_object.a,\n  on main.tf line 1\n"
             "Error: creating thing: boom\n\n  with module.net.aws_subnet.b[0],\n  on x.tf line 2\n")
    findings = failure_findings("apply", error)
    assert [f["address"] for f in findings] == ["aws_s3_object.a", "module.net.aws_subnet.b[0]"]
    assert all(f["rule_id"] == "GO-SHADOW-001" and f["severity"] == "HIGH" for f in findings)
    assert "creating thing: boom" in findings[0]["message"]
    assert [f["address"] for f in failure_findings("init", "Error: no provider")] == ["(terraform init)"]


def test_rejects_non_terraform_dir(tmp_path):
    with pytest.raises(ShadowError, match="no \\*.tf files"):
        run_shadow(tmp_path)


# --- integration: real Terraform against MiniStack ---------------------------------


@integration
def test_good_demo_applies():
    result = run_shadow(DEMO / "good")
    assert result.success and result.stage == "complete"
    assert [(r["address"], r["id"]) for r in result.resources] == [
        ("aws_cloudwatch_metric_alarm.bucket_size", "ghostops-good-logs-bucket-size"),
        ("aws_s3_bucket.logs", "ghostops-good-logs-bucket"),
    ]
    assert result.planned_changes == 2 and result.findings == [] and result.error is None
    assert_ministack_empty()


@integration
def test_bad_demo_applies_risk_is_static_analysis_job():
    result = run_shadow(DEMO / "bad")
    assert result.success, result.error
    assert {r["address"] for r in result.resources} == {
        "aws_db_instance.unencrypted", "aws_iam_policy.admin_star", "aws_instance.web",
        "aws_s3_bucket.public", "aws_s3_bucket_acl.public", "aws_s3_bucket_ownership_controls.public",
        "aws_s3_bucket_public_access_block.public", "aws_security_group.ssh_open",
    }
    assert all(r["id"] for r in result.resources)
    assert_ministack_empty()


@integration
def test_failed_apply_is_a_finding_with_partial_state(tmp_path):
    config = write_config(tmp_path / "cfg", """
resource "aws_s3_bucket" "ok" {
  bucket = "ghostops-shadow-ok"
}
resource "aws_s3_object" "orphan" {
  bucket  = "ghostops-bucket-that-does-not-exist"
  key     = "hello.txt"
  content = "hello"
}
""")
    result = run_shadow(config)
    assert not result.success and result.stage == "apply"
    assert "NoSuchBucket" in result.error
    assert [f["address"] for f in result.findings] == ["aws_s3_object.orphan"]
    assert [r["address"] for r in result.resources] == ["aws_s3_bucket.ok"]  # created before the failure
    assert_ministack_empty()


@integration
def test_failed_plan_is_a_finding(tmp_path):
    config = write_config(tmp_path / "cfg", 'resource "aws_s3_bucket" "b" {\n  bucket = aws_s3_bucket.missing.id\n}\n')
    result = run_shadow(config)
    assert not result.success and result.stage == "plan"
    assert "Reference to undeclared resource" in result.error
    assert [f["address"] for f in result.findings] == ["(terraform plan)"]
    assert result.resources == []


@integration
def test_invalid_value_rejected_by_ministack_at_apply(tmp_path):
    config = write_config(tmp_path / "cfg", 'resource "aws_s3_bucket" "b" {\n  bucket = "Not_A_Valid_Bucket"\n}\n')
    result = run_shadow(config)
    assert not result.success and result.stage == "apply"
    assert "InvalidBucketName" in result.error
    assert [f["address"] for f in result.findings] == ["aws_s3_bucket.b"]


@integration
def test_runs_do_not_leak_into_each_other():
    client("s3").create_bucket(Bucket="leftover-from-someone-else")
    first = run_shadow(DEMO / "good")
    second = run_shadow(DEMO / "good")  # same bucket name: would fail if the first run leaked
    assert first.success and second.success
    assert "leftover-from-someone-else" not in {r["id"] for r in first.resources}
    assert_ministack_empty()
