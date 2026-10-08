import json
import subprocess
from pathlib import Path

import pytest

from app.plan_parser import PlanParseError
from app.policy_engine import RULES_DIR, Finding, PolicyEngineError, evaluate, evaluate_file, find_opa

FIXTURES = Path(__file__).parent / "fixtures"
REGO_TESTS = Path(__file__).parent / "rego"


def summary(findings: list[Finding]) -> set[tuple[str, str, str, str]]:
    return {(f.decision, f.rule_id, f.severity, f.address) for f in findings}


# --- every rule fires on a bad config --------------------------------------


def test_bad_plan_fires_each_deny_rule_exactly_once():
    findings = [f for f in evaluate_file(FIXTURES / "bad_plan.json") if f.decision == "deny"]
    assert summary(findings) == {
        ("deny", "GO-SG-001", "CRITICAL", "aws_security_group.ssh_open"),
        ("deny", "GO-IAM-001", "CRITICAL", "aws_iam_policy.admin_star"),
        ("deny", "GO-S3-001", "HIGH", "aws_s3_bucket_acl.public"),
        ("deny", "GO-RDS-001", "HIGH", "aws_db_instance.unencrypted"),
    }
    assert len(findings) == 4
    assert {f.pillar for f in findings} == {"security"}


def test_bad_plan_advisory_findings_by_pillar():
    findings = [f for f in evaluate_file(FIXTURES / "bad_plan.json") if f.decision == "warn"]
    assert {(f.pillar, f.rule_id, f.severity, f.address) for f in findings} == {
        ("reliability", "GO-REL-001", "MEDIUM", "aws_db_instance.unencrypted"),
        ("reliability", "GO-REL-003", "MEDIUM", "aws_s3_bucket.public"),
        ("reliability", "GO-REL-004", "MEDIUM", "aws_instance.web"),
        ("reliability", "GO-REL-006", "LOW", "aws_db_instance.unencrypted"),
        ("security", "GO-S3-002", "LOW", "aws_s3_bucket.public"),
        ("cost", "GO-COST-003", "LOW", "aws_s3_bucket.public"),
        ("cost", "GO-COST-003", "LOW", "aws_db_instance.unencrypted"),
    }


def test_bad_plan_messages_are_plain_and_name_the_resource():
    by_rule = {f.rule_id: f.message for f in evaluate_file(FIXTURES / "bad_plan.json")}
    assert by_rule["GO-SG-001"] == (
        "aws_security_group.ssh_open allows SSH (port 22) from 0.0.0.0/0, i.e. from anywhere on the internet."
    )
    assert "full administrator access" in by_rule["GO-IAM-001"]
    assert '"public-read"' in by_rule["GO-S3-001"]
    assert "storage_encrypted must be true" in by_rule["GO-RDS-001"]


def test_findings_are_sorted_most_severe_first():
    severities = [f.severity for f in evaluate_file(FIXTURES / "bad_plan.json")]
    assert severities == ["CRITICAL", "CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM", "LOW", "LOW", "LOW", "LOW"]


def test_destroy_plan_warns_on_every_deletion():
    findings = evaluate_file(FIXTURES / "good_destroy_plan.json")
    assert summary(findings) == {
        ("warn", "GO-DEL-001", "MEDIUM", "aws_s3_bucket.logs"),
        ("warn", "GO-DEL-001", "MEDIUM", "aws_cloudwatch_metric_alarm.bucket_size"),
    }
    assert all("will be destroyed" in f.message for f in findings)


# --- nothing blocking fires on the good config ---------------------------------


@pytest.mark.parametrize("fixture", ["good_plan.json", "good_modified_plan.json"])
def test_good_config_has_only_advisory_findings(fixture):
    # The good demo bucket has no versioning or encryption resource: advisory only.
    findings = evaluate_file(FIXTURES / fixture)
    assert not [f for f in findings if f.decision == "deny"]
    assert {(f.pillar, f.rule_id, f.severity) for f in findings} <= {
        ("reliability", "GO-REL-003", "MEDIUM"), ("security", "GO-S3-002", "LOW")}


def test_unchanged_plan_has_no_findings():
    assert evaluate_file(FIXTURES / "good_noop_plan.json") == []


# --- Rego unit tests and compile checks --------------------------------------


def test_rego_compiles_in_strict_mode():
    proc = subprocess.run(
        [find_opa(), "check", "--strict", str(RULES_DIR), str(REGO_TESTS)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_rego_unit_tests_pass():
    proc = subprocess.run(
        [find_opa(), "test", str(RULES_DIR), str(REGO_TESTS), "--format", "json"], capture_output=True, text=True
    )
    results = json.loads(proc.stdout)
    failed = [r["name"] for r in results if r.get("fail") or r.get("error")]
    assert proc.returncode == 0 and not failed, failed or proc.stderr
    assert len(results) >= 70


# --- failure handling: never silently "no findings" -----------------------------


def test_malformed_plan_is_rejected_before_opa():
    with pytest.raises(PlanParseError):
        evaluate({"resource_changes": []})


def test_missing_rules_fail_closed(tmp_path):
    with pytest.raises(PolicyEngineError, match="no value for data.ghostops.result"):
        evaluate({"format_version": "1.2", "resource_changes": []}, rules_dir=tmp_path)


def test_broken_rego_fails_closed(tmp_path):
    (tmp_path / "broken.rego").write_text("package ghostops\n\ndeny contains x if {\n", encoding="utf-8")
    with pytest.raises(PolicyEngineError, match="opa eval failed"):
        evaluate({"format_version": "1.2", "resource_changes": []}, rules_dir=tmp_path)


def test_missing_opa_binary_is_reported(monkeypatch, tmp_path):
    monkeypatch.setenv("GHOSTOPS_OPA_BIN", str(tmp_path / "nope.exe"))
    with pytest.raises(PolicyEngineError, match="GHOSTOPS_OPA_BIN points to a missing file"):
        evaluate({"format_version": "1.2", "resource_changes": []})


def test_cli_exit_codes():
    def run(fixture):
        return subprocess.run(
            [__import__("sys").executable, "-m", "app.policy_engine", str(FIXTURES / fixture)],
            capture_output=True, text=True, cwd=Path(__file__).parent.parent,
        )

    bad = run("bad_plan.json")
    assert bad.returncode == 1
    assert "DENY CRITICAL security    GO-SG-001" in bad.stdout
    good = run("good_plan.json")
    assert good.returncode == 0  # warnings only
    assert "WARN MEDIUM   reliability GO-REL-003" in good.stdout
    empty = run("good_noop_plan.json")
    assert empty.returncode == 0 and empty.stdout.strip() == "no findings"
