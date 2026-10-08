import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.catalog import CATALOG, catalog, defaults
from app.cost import CostError, plan_cost
from app.generator import ArchitectureError, generate, hcl_string, validate
from app.plan_parser import parse_plan
from app.policy_engine import evaluate
from app.shadow import ShadowError, ministack_version, run_shadow, shadow_env

MIXED = {"services": [
    {"type": "vpc", "config": {"name": "core"}},
    {"type": "ec2", "config": {"name": "web", "count": 2, "instance_type": "t3.small", "volume_gb": 30}},
    {"type": "s3", "config": {"name": "assets", "size_gb": 50}},
    {"type": "rds", "config": {"name": "orders-db", "storage_gb": 50}},
    {"type": "iam", "config": {"name": "app", "actions": ["s3:GetObject", "s3:PutObject"]}},
    {"type": "lambda", "config": {"name": "thumbnailer", "memory_mb": 512}},
    {"type": "dynamodb", "config": {"name": "sessions"}},
    {"type": "cloudwatch_alarm", "config": {"name": "web-cpu"}},
    {"type": "alb", "config": {"name": "front"}},
]}

RISKY = {"services": [
    {"type": "ec2", "config": {"name": "bastion", "ssh_source_cidr": "0.0.0.0/0"}},
    {"type": "s3", "config": {"name": "leaky", "public_access": True}},
    {"type": "iam", "config": {"name": "god", "actions": ["*"], "resource": "*"}},
    {"type": "rds", "config": {"name": "plain-db", "encrypted": False}},
]}


# --- catalog ---------------------------------------------------------------------------------------


def test_catalog_lists_exactly_the_requested_services():
    assert [s["type"] for s in catalog()] == [
        "ec2", "s3", "rds", "vpc", "iam", "lambda", "dynamodb", "cloudwatch_alarm", "alb"]


def test_catalog_entries_are_well_formed():
    for service in catalog():
        assert service["shadow_supported"] is True or service["pricing"] != "unsupported", service["type"]
        assert service["pricing"] in {"fixed", "usage_based", "free", "unsupported"}
        assert service["pricing_note"] and service["label"] and service["description"]
        names = [f["name"] for f in service["fields"]]
        assert names[0] == "name" and len(names) == len(set(names))
        for f in service["fields"]:
            assert f["kind"] in {"select", "int", "bool", "cidr", "string", "list"}
            if f["kind"] == "select":
                assert f["default"] in f["options"]
            if f["kind"] == "int":
                assert f["min"] <= f["default"] <= f["max"]


def test_requested_form_fields_exist():
    fields = {t: {f["name"] for f in spec["fields"]} for t, spec in CATALOG.items()}
    assert {"instance_type", "count", "volume_gb", "ssh_source_cidr"} <= fields["ec2"]
    assert {"public_access", "versioning", "encryption", "size_gb"} <= fields["s3"]
    assert {"engine", "instance_class", "storage_gb", "multi_az", "encrypted", "publicly_accessible"} <= fields["rds"]


def test_catalog_is_a_copy():
    catalog()[0]["fields"].clear()
    assert CATALOG["ec2"]["fields"]


def test_defaults_are_safe():
    assert defaults("ec2")["ssh_source_cidr"] == "10.0.0.0/16"
    assert defaults("s3")["public_access"] is False and defaults("s3")["encryption"] is True
    assert defaults("rds")["encrypted"] is True and defaults("rds")["publicly_accessible"] is False
    assert defaults("alb")["internal"] is True
    assert defaults("iam")["actions"] == ["s3:GetObject"]


# --- generation ------------------------------------------------------------------------------------


EXPECTED_BLOCKS = {
    "ec2": ["aws_security_group.ec2_1_ssh", "aws_instance.ec2_1", "aws_ebs_volume.ec2_1", "aws_volume_attachment.ec2_1"],
    "s3": ["aws_s3_bucket.s3_1", "aws_s3_bucket_versioning.s3_1",
           "aws_s3_bucket_server_side_encryption_configuration.s3_1", "aws_s3_bucket_public_access_block.s3_1"],
    "rds": ["aws_db_instance.rds_1"],
    "vpc": ["aws_vpc.vpc_1", "aws_subnet.vpc_1", "aws_security_group.vpc_1"],
    "iam": ["aws_iam_role.iam_1", "aws_iam_policy.iam_1", "aws_iam_role_policy_attachment.iam_1"],
    "lambda": ["data.archive_file.lambda_1", "aws_iam_role.lambda_1_exec", "aws_lambda_function.lambda_1"],
    "dynamodb": ["aws_dynamodb_table.dynamodb_1"],
    "cloudwatch_alarm": ["aws_cloudwatch_metric_alarm.cloudwatch_alarm_1"],
    "alb": ["aws_vpc.alb_1", "aws_subnet.alb_1", "aws_security_group.alb_1", "aws_lb.alb_1",
            "aws_lb_target_group.alb_1", "aws_lb_listener.alb_1"],
}


@pytest.mark.parametrize("stype", list(CATALOG))
def test_each_service_generates_with_defaults(stype):
    g = generate({"services": [{"type": stype}]})
    assert g.resources == EXPECTED_BLOCKS[stype]
    assert 'access_key                  = "test"' in g.main_tf
    assert ("hashicorp/archive" in g.main_tf) is (stype == "lambda")


def test_optional_blocks_follow_config():
    public = generate({"services": [{"type": "s3", "config": {"public_access": True, "versioning": False,
                                                              "encryption": False}}]})
    assert "aws_s3_bucket_acl.s3_1" in public.resources and "aws_s3_bucket_versioning.s3_1" not in public.resources
    assert 'acl        = "public-read"' in public.main_tf
    internet_alb = generate({"services": [{"type": "alb", "config": {"internal": False}}]})
    assert "aws_internet_gateway.alb_1" in internet_alb.resources
    provisioned = generate({"services": [{"type": "dynamodb", "config": {"billing_mode": "PROVISIONED"}}]}).main_tf
    assert "read_capacity  = 5" in provisioned
    ipv6 = generate({"services": [{"type": "ec2", "config": {"ssh_source_cidr": "::/0"}}]}).main_tf
    assert 'ipv6_cidr_blocks = ["::/0"]' in ipv6


def test_generation_is_deterministic():
    assert generate(MIXED).main_tf == generate(json.loads(json.dumps(MIXED))).main_tf


def test_auto_names_and_s3_suffix():
    services = validate({"services": [{"type": "ec2"}, {"type": "ec2"}, {"type": "s3", "config": {"name": "logs"}}]})
    assert [s.slug for s in services] == ["ec2-1", "ec2-2", "logs"]
    assert [s.ident for s in services] == ["ec2_1", "ec2_2", "logs"]
    assert '"ghostops-logs-' in generate({"services": [{"type": "s3", "config": {"name": "logs"}}]}).main_tf


@pytest.mark.parametrize(("body", "field", "message"), [
    ({}, "services", "body must be"),
    ({"services": []}, "services", "between 1 and"),
    ({"services": [{"type": "redshift"}]}, "type", "must be one of"),
    ({"services": [{"type": "ec2", "config": {"cpu": 4}}]}, "cpu", "unknown field"),
    ({"services": [{"type": "ec2", "config": {"count": 11}}]}, "count", "between 1 and 10"),
    ({"services": [{"type": "ec2", "config": {"count": True}}]}, "count", "must be an integer"),
    ({"services": [{"type": "ec2", "config": {"instance_type": "p5.48xlarge"}}]}, "instance_type", "must be one of"),
    ({"services": [{"type": "ec2", "config": {"ssh_source_cidr": "10.0.0.1/16"}}]}, "ssh_source_cidr", "not a valid CIDR"),
    ({"services": [{"type": "s3", "config": {"versioning": "yes"}}]}, "versioning", "true or false"),
    ({"services": [{"type": "iam", "config": {"actions": []}}]}, "actions", "1 to 20"),
    ({"services": [{"type": "iam", "config": {"actions": ["s3:Get Object"]}}]}, "actions", "invalid entries"),
    ({"services": [{"type": "vpc", "config": {"cidr_block": "10.0.0.0/8"}}]}, "cidr_block", "/16 to /24"),
    ({"services": [{"type": "ec2", "config": {"name": "Web_Server"}}]}, "name", "must match"),
    ({"services": [{"type": "ec2", "config": {"name": "a"}}, {"type": "s3", "config": {"name": "a"}}]}, "name", "duplicate"),
    ({"services": [{"type": "dynamodb", "config": {"hash_key": "id\" } evil {"}}]}, "hash_key", "must match"),
])
def test_validation_errors(body, field, message):
    with pytest.raises(ArchitectureError) as exc:
        generate(body)
    assert any(e["field"] == field and message in e["message"] for e in exc.value.errors), exc.value.errors


def test_all_errors_reported_at_once():
    with pytest.raises(ArchitectureError) as exc:
        generate({"services": [{"type": "ec2", "config": {"count": 0, "volume_gb": 0}}, {"type": "nope"}]})
    assert {(e["service"], e["field"]) for e in exc.value.errors} == {(0, "count"), (0, "volume_gb"), (1, "type")}


def test_strings_cannot_inject_terraform():
    assert hcl_string('a"b') == '"a\\"b"'
    assert hcl_string("${var.x}") == '"$${var.x}"'
    assert hcl_string("%{ if true }") == '"%%{ if true }"'
    tf = generate({"services": [{"type": "iam", "config": {"resource": "arn:aws:s3:::b/${aws_iam_role.x.arn}"}}]}).main_tf
    assert 'Resource = "arn:aws:s3:::b/$${aws_iam_role.x.arn}"' in tf


# --- integration: real Terraform, OPA, MiniStack, Infracost -----------------------------------------


def terraform(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["terraform", *args, "-no-color"], cwd=cwd, env=shadow_env(cwd),
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)


def planned(tmp_path_factory, name: str, architecture: dict) -> tuple[Path, dict]:
    workdir = tmp_path_factory.mktemp(name)
    generate(architecture).write(workdir)
    for args in (["init", "-input=false"], ["validate"], ["plan", "-input=false", "-out=tf.plan"]):
        proc = terraform(workdir, *args)
        assert proc.returncode == 0, f"terraform {args[0]} failed:\n{proc.stdout}{proc.stderr}"
    shown = terraform(workdir, "show", "-json", "tf.plan")
    return workdir, json.loads(shown.stdout)


needs_terraform = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")


@pytest.fixture(scope="module")
def mixed_plan(tmp_path_factory):
    return planned(tmp_path_factory, "mixed", MIXED)


@pytest.mark.integration
@needs_terraform
def test_mixed_architecture_is_formatted_valid_and_plans(mixed_plan):
    workdir, plan = mixed_plan
    fmt = subprocess.run(["terraform", "fmt", "-check", "-diff"], cwd=workdir, capture_output=True, text=True)
    assert fmt.returncode == 0, fmt.stdout
    changes = parse_plan(plan)
    assert len(changes) == 30 and {c.action for c in changes} == {"create"}
    assert {c.type for c in changes} >= {
        "aws_instance", "aws_ebs_volume", "aws_s3_bucket", "aws_db_instance", "aws_vpc", "aws_iam_policy",
        "aws_lambda_function", "aws_dynamodb_table", "aws_cloudwatch_metric_alarm", "aws_lb"}


@pytest.mark.integration
@needs_terraform
def test_safe_defaults_pass_every_policy(mixed_plan):
    assert [f for f in evaluate(mixed_plan[1]) if f.decision == "deny"] == []


@pytest.mark.integration
@needs_terraform
def test_risky_options_trigger_the_matching_rules(tmp_path_factory):
    _, plan = planned(tmp_path_factory, "risky", RISKY)
    denied = {(f.rule_id, f.address) for f in evaluate(plan) if f.decision == "deny"}
    assert denied == {
        ("GO-SG-001", "aws_security_group.bastion_ssh"),
        ("GO-S3-001", "aws_s3_bucket_acl.leaky"),
        ("GO-IAM-001", "aws_iam_policy.god"),
        ("GO-RDS-001", "aws_db_instance.plain_db"),
    }


def ministack_up() -> bool:
    try:
        ministack_version()
        return True
    except ShadowError:
        return False


@pytest.mark.integration
@pytest.mark.skipif(not ministack_up(), reason="MiniStack not running (docker compose up -d)")
def test_mixed_architecture_applies_on_ministack(tmp_path):
    """Re-checks every shadow_supported=True claim in the catalog in one apply."""
    generate(MIXED).write(tmp_path)
    result = run_shadow(tmp_path)
    assert result.success, result.error
    created = {r["address"].split("[")[0].rsplit(".", 1)[0] for r in result.resources}
    for stype, spec in CATALOG.items():
        if spec["shadow_supported"]:
            assert set(spec["resources"]) & created, f"{stype}: none of {spec['resources']} was created"


def infracost_ready() -> bool:
    try:
        from app.cost import check_login
        check_login()
        return True
    except CostError:
        return False


@pytest.mark.integration
@needs_terraform
@pytest.mark.skipif(not infracost_ready(), reason="Infracost not logged in")
def test_catalog_pricing_claims_match_infracost(mixed_plan):
    by_type: dict[str, list] = {}
    for r in plan_cost(mixed_plan[1])["resources"]:
        by_type.setdefault(r["type"], []).append(r["after_usd"])
    for stype, spec in CATALOG.items():
        prices = [p for rtype in spec["resources"] for p in by_type.get(rtype, [])]
        if spec["pricing"] == "fixed":
            assert any(p and p > 0 for p in prices), f"{stype}: expected a non-zero price, got {prices}"
        elif spec["pricing"] == "unsupported":
            assert None in prices, f"{stype}: expected an unpriced resource, got {prices}"
        else:  # usage_based or free: supported, $0 without usage data
            assert prices and all(p == 0 for p in prices), f"{stype}: expected $0, got {prices}"
