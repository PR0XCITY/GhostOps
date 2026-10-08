import json
import shutil
from pathlib import Path

import pytest

from app import catalog as catalog_module
from app import certificate, remediation
from app.architecture import analyze_architecture
from app.certificate import AUTO_APPROVED, BLOCKED, verify
from app.cost import CostError, to_yaml
from app.generator import ArchitectureError, generate
from app.remediation import apply_config_changes, groq_facts, remediate, template_remediation
from app.shadow import ShadowError, ShadowResult, ministack_version

SECRET = "arch-test-secret-" + "f00d" * 8
FIXTURES = Path(__file__).parent / "fixtures"

WEB_APP = {"services": [
    {"type": "vpc", "config": {"name": "core"}},
    {"type": "ec2", "config": {"name": "web", "count": 2, "instance_type": "t3.small", "volume_gb": 40}},
    {"type": "alb", "config": {"name": "front"}},
    {"type": "rds", "config": {"name": "orders-db", "storage_gb": 50}},
    {"type": "cloudwatch_alarm", "config": {"name": "web-cpu"}},
]}

SERVERLESS = {"services": [
    {"type": "lambda", "config": {"name": "api", "memory_mb": 512},
     "usage": {"monthly_requests": 5_000_000, "request_duration_ms": 120}},
    {"type": "dynamodb", "config": {"name": "orders"},
     "usage": {"monthly_write_request_units": 2_000_000, "monthly_read_request_units": 10_000_000, "storage_gb": 20}},
    {"type": "s3", "config": {"name": "uploads", "size_gb": 500},
     "usage": {"monthly_get_requests": 2_000_000, "monthly_put_requests": 200_000}},
    {"type": "iam", "config": {"name": "api-reader", "trusted_service": "lambda.amazonaws.com"}},
]}

RISKY = {"services": [
    {"type": "ec2", "config": {"name": "bastion", "ssh_source_cidr": "0.0.0.0/0"}},
    {"type": "s3", "config": {"name": "leaky", "public_access": True}},
    {"type": "iam", "config": {"name": "god", "actions": ["*"], "resource": "*"}},
    {"type": "rds", "config": {"name": "plain-db", "encrypted": False, "publicly_accessible": True}},
]}


@pytest.fixture(autouse=True)
def no_real_groq(monkeypatch):
    monkeypatch.setattr(certificate, "setting", lambda name, default=None:
                        {"GHOSTOPS_HMAC_SECRET": SECRET}.get(name, default))


def flag(rule, resource, severity="HIGH"):
    return {"rule": rule, "severity": severity, "resource": resource, "message": "m"}


# --- remediation rules ------------------------------------------------------------------------------


def test_service_level_fixes_for_risky_architecture():
    g = generate(RISKY)
    cases = {
        ("GO-SG-001", "aws_security_group.bastion_ssh"): [("bastion", "ssh_source_cidr", "0.0.0.0/0", "10.0.0.0/16")],
        ("GO-EXPOSE-001", "aws_instance.bastion[0]"): [("bastion", "ssh_source_cidr", "0.0.0.0/0", "10.0.0.0/16")],
        ("GO-S3-001", "aws_s3_bucket_acl.leaky"): [("leaky", "public_access", True, False)],
        ("GO-EXPOSE-001", "aws_s3_bucket.leaky"): [("leaky", "public_access", True, False)],
        ("GO-IAM-001", "aws_iam_policy.god"): [("god", "actions", ["*"], ["s3:GetObject"]),
                                               ("god", "resource", "*", "arn:aws:s3:::example-bucket/*")],
        ("GO-RDS-001", "aws_db_instance.plain_db"): [("plain-db", "encrypted", False, True)],
    }
    for (rule, resource), expected in cases.items():
        changes, text = template_remediation(flag(rule, resource), g)
        assert [(c["service"], c["field"], c["from"], c["to"]) for c in changes] == expected, rule
        assert text and changes[0]["field"] in text


def test_terraform_level_fixes_without_architecture():
    changes, text = template_remediation(flag("GO-SG-001", "aws_security_group.ssh_open"))
    assert changes == [{"resource": "aws_security_group.ssh_open", "attribute": "ingress.cidr_blocks",
                        "to": ["10.0.0.0/16"]}]
    assert template_remediation(flag("GO-RDS-001", "aws_db_instance.x"))[0][0]["attribute"] == "storage_encrypted"
    assert template_remediation(flag("GO-DEL-001", "aws_s3_bucket.x", "MEDIUM"))[0][0]["attribute"] == \
        "lifecycle.prevent_destroy"
    changes, text = template_remediation(flag("GO-SHADOW-001", "(shadow run)"))
    assert changes == [] and "shadow_run.error" in text


def test_groq_sees_rule_type_and_our_fix_but_never_user_values():
    g = generate(RISKY)
    flags = [flag("GO-SG-001", "aws_security_group.bastion_ssh"), flag("GO-IAM-001", "aws_iam_policy.god", "CRITICAL")]
    fixes = [template_remediation(f, g)[0] for f in flags]
    facts = groq_facts(flags, fixes)
    outbound = json.dumps(facts)
    assert facts[0] == {"rule": "GO-SG-001", "title": "SSH or RDP open to the internet", "severity": "HIGH",
                        "resource_type": "aws_security_group",
                        "fix": [{"field": "ssh_source_cidr", "set_to": "10.0.0.0/16"}]}
    for leak in ("0.0.0.0/0", "bastion", "god", '"*"', "aws_security_group.bastion_ssh", "arn:aws"):
        assert leak not in outbound, leak
    assert {"field": "resource", "set_to": "a specific resource ARN"} in facts[1]["fix"]


def test_redacted_groq_sentence_falls_back_for_that_flag_only(monkeypatch):
    monkeypatch.setattr(certificate, "setting", lambda name, default=None: {"GROQ_API_KEY": "gsk_FAKE"}.get(name, default))
    monkeypatch.setattr(certificate, "_post_json", lambda *a, **k: {"choices": [{"message": {"content": json.dumps(
        {"remediations": ["Turn off public access on the bucket right away.",
                          "Point the policy at arn:aws:s3:::secret-bucket/* only."]})}}]})
    rems = remediate([flag("GO-S3-001", "aws_s3_bucket_acl.leaky"), flag("GO-IAM-001", "aws_iam_policy.god")],
                     generate(RISKY))
    assert [r["generated_by"] for r in rems] == ["groq", "template"]
    assert "[redacted]" not in rems[1]["summary"] and "least privilege" in rems[1]["summary"]


def test_groq_sentences_used_when_valid(monkeypatch):
    sent = {}

    def fake_post(url, body, headers, timeout):
        sent["body"] = body
        n = len(json.loads(body["messages"][1]["content"])["findings"])
        return {"choices": [{"message": {"content": json.dumps(
            {"remediations": [f"Set the field to the safe value number {i}." for i in range(n)]})}}]}

    monkeypatch.setattr(certificate, "setting", lambda name, default=None: {"GROQ_API_KEY": "gsk_FAKE"}.get(name, default))
    monkeypatch.setattr(certificate, "_post_json", fake_post)
    rems = remediate([flag("GO-S3-001", "aws_s3_bucket_acl.leaky"), flag("GO-RDS-001", "aws_db_instance.plain_db")],
                     generate(RISKY))
    assert [r["generated_by"] for r in rems] == ["groq", "groq"]
    assert rems[1]["summary"] == "Set the field to the safe value number 1."
    assert rems[1]["config_change"][0]["field"] == "encrypted"  # the change itself never comes from the LLM


@pytest.mark.parametrize("reply", [
    {"choices": [{"message": {"content": "not json"}}]},
    {"choices": [{"message": {"content": json.dumps({"remediations": ["only one sentence for two flags"]})}}]},
    {"choices": [{"message": {"content": json.dumps({"remediations": ["ok sentence long enough", 5]})}}]},
])
def test_groq_bad_answers_fall_back_to_templates(monkeypatch, reply):
    monkeypatch.setattr(certificate, "setting", lambda name, default=None: {"GROQ_API_KEY": "gsk_FAKE"}.get(name, default))
    monkeypatch.setattr(certificate, "_post_json", lambda *a, **k: reply)
    rems = remediate([flag("GO-S3-001", "aws_s3_bucket_acl.leaky"), flag("GO-RDS-001", "aws_db_instance.plain_db")],
                     generate(RISKY))
    assert {r["generated_by"] for r in rems} == {"template"}
    assert "public_access" in rems[0]["summary"]


def test_apply_config_changes():
    rems = remediate([flag("GO-SG-001", "aws_security_group.bastion_ssh"), flag("GO-IAM-001", "aws_iam_policy.god")],
                     generate(RISKY), use_groq=False)
    fixed = apply_config_changes(RISKY, rems)
    by_name = {s["config"]["name"]: s["config"] for s in fixed["services"]}
    assert by_name["bastion"]["ssh_source_cidr"] == "10.0.0.0/16"
    assert by_name["god"] == {"name": "god", "actions": ["s3:GetObject"], "resource": "arn:aws:s3:::example-bucket/*"}
    assert RISKY["services"][0]["config"]["ssh_source_cidr"] == "0.0.0.0/0"  # input untouched


# --- usage inputs ------------------------------------------------------------------------------------


def test_usage_inputs_and_infracost_usage_file():
    g = generate(SERVERLESS)
    assert g.usage_inputs()["aws_s3_bucket.uploads"] == {"storage_gb": 500, "monthly_put_requests": 200_000,
                                                         "monthly_get_requests": 2_000_000}
    assert g.usage_file()["aws_s3_bucket.uploads"] == {"standard": {
        "storage_gb": 500, "monthly_tier_1_requests": 200_000, "monthly_tier_2_requests": 2_000_000}}
    assert g.usage_file()["aws_lambda_function.api"] == {"monthly_requests": 5_000_000, "request_duration_ms": 120}
    assert "aws_iam_role.api_reader" not in g.usage_file()
    assert to_yaml({"version": "0.1", "resource_usage": {"aws_s3_bucket.uploads": {"standard": {"storage_gb": 500}}}}) == (
        'version: "0.1"\nresource_usage:\n  aws_s3_bucket.uploads:\n    standard:\n      storage_gb: 500')


@pytest.mark.parametrize(("service", "field", "message"), [
    ({"type": "ec2", "usage": {"monthly_requests": 1}}, "usage", "no usage inputs"),
    ({"type": "lambda", "usage": {"cold_starts": 3}}, "usage.cold_starts", "unknown usage input"),
    ({"type": "lambda", "usage": {"monthly_requests": -1}}, "usage.monthly_requests", "between 0"),
    ({"type": "s3", "usage": "lots"}, "usage", "must be an object"),
])
def test_usage_validation(service, field, message):
    with pytest.raises(ArchitectureError) as exc:
        generate({"services": [service]})
    assert any(e["field"] == field and message in e["message"] for e in exc.value.errors), exc.value.errors


def test_yaml_rejects_unsafe_keys():
    with pytest.raises(CostError):
        to_yaml({"bad key: injected": 1})


# --- static-only services ------------------------------------------------------------------------------


def plan_stub(_directory):
    return json.loads((FIXTURES / "good_plan.json").read_text(encoding="utf-8"))


NO_COST = {"monthly_delta_usd": 0.0, "complete": True, "unpriced": [], "resources": []}


def test_static_only_service_is_left_out_of_the_shadow_apply(monkeypatch):
    monkeypatch.setitem(catalog_module.CATALOG["alb"], "shadow_supported", False)
    applied_tf = {}

    def shadow(directory):
        applied_tf["main"] = Path(directory, "main.tf").read_text(encoding="utf-8")
        return ShadowResult(True, "complete", resources=[{"address": "x"}], inventory=[{"type": "aws_s3_bucket", "id": "b"}])

    cert = analyze_architecture({"services": [{"type": "s3", "config": {"name": "data"}},
                                              {"type": "alb", "config": {"name": "front"}}]},
                                planner=plan_stub, shadow_runner=shadow, use_groq=False, cost_result=NO_COST, secret=SECRET)
    assert 'resource "aws_lb"' not in applied_tf["main"] and 'resource "aws_s3_bucket" "data"' in applied_tf["main"]
    assert 'resource "aws_lb" "front"' in cert["generated_terraform"]  # still statically analysed
    modes = {s["name"]: s["analysis"] for s in cert["architecture"]["services"]}
    assert modes == {"data": "shadow_and_static", "front": "static_only"}
    assert cert["shadow_run"]["resources"] == [{"type": "aws_s3_bucket", "id": "b"}]
    assert verify(cert, secret=SECRET)


def test_all_static_only_means_unverified_and_blocked(monkeypatch):
    monkeypatch.setitem(catalog_module.CATALOG["alb"], "shadow_supported", False)

    def never(_d):
        raise AssertionError("shadow must not run")

    cert = analyze_architecture({"services": [{"type": "alb"}]}, planner=plan_stub, shadow_runner=never,
                                use_groq=False, cost_result=NO_COST, secret=SECRET)
    assert cert["verdict"] == BLOCKED and cert["shadow_run"]["applied"] is False
    assert "static analysis only" in cert["shadow_run"]["error"]
    assert cert["architecture"]["services"][0]["analysis"] == "static_only"


# --- static check (builder) ----------------------------------------------------------------------------------


def test_check_endpoint_is_static_unsigned_and_not_stored(tmp_path):
    from functools import partial

    from fastapi.testclient import TestClient

    from app.api import create_app
    from app.architecture import check_architecture
    from app.store import Store

    def plan_for_risky_ec2(directory):
        # a real-shaped plan: SG with SSH open to the world, as the generator would produce
        return {"format_version": "1.2", "resource_changes": [{
            "address": "aws_security_group.bastion_ssh", "mode": "managed", "type": "aws_security_group",
            "name": "bastion_ssh", "change": {"actions": ["create"], "before": None, "after": {
                "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                             "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}]}}}]}

    store = Store(tmp_path / "db")
    checker = partial(check_architecture, planner=plan_for_risky_ec2, cost_result=NO_COST)
    with TestClient(create_app(store=store, architecture_checker=checker)) as client:
        r = client.post("/architectures/check", json={"services": [
            {"type": "ec2", "config": {"name": "bastion", "ssh_source_cidr": "0.0.0.0/0"}}]})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["static_only"] is True and out["verdict_preview"] == BLOCKED
        assert "signature" not in out and store.list_certificates() == []
        [sg_flag] = [f for f in out["risk_flags"] if f["rule"] == "GO-SG-001"]
        assert sg_flag["remediation"]["config_change"][0]["to"] == "10.0.0.0/16"
        assert sg_flag["remediation"]["generated_by"] == "template"
        assert out["services"][0]["resources"][0] == "aws_security_group.bastion_ssh"
        assert 'resource "aws_instance" "bastion"' in out["generated_terraform"]
        bad = client.post("/architectures/check", json={"services": [{"type": "ec2", "config": {"count": 0}}]})
        assert bad.status_code == 422 and bad.json()["detail"]["errors"][0]["field"] == "count"


# --- live: 3 architectures through the whole pipeline ----------------------------------------------------


def ministack_up():
    try:
        ministack_version()
        return True
    except ShadowError:
        return False


def live(test):
    marks = [pytest.mark.integration,
             pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform missing"),
             pytest.mark.skipif(not ministack_up(), reason="MiniStack not running")]
    for m in marks:
        test = m(test)
    return test


def by_type(items, key="type"):
    out = {}
    for item in items:
        out.setdefault(item[key], []).append(item)
    return out


@pytest.fixture
def real_settings(monkeypatch):
    monkeypatch.setattr(certificate, "setting", __import__("app.config", fromlist=["setting"]).setting)


INVENTORIED_ID = {  # Terraform state id -> what boto3 reports for that type
    "aws_instance", "aws_ebs_volume", "aws_vpc", "aws_subnet", "aws_security_group", "aws_db_instance",
    "aws_lb", "aws_lb_target_group", "aws_lb_listener", "aws_cloudwatch_metric_alarm", "aws_s3_bucket",
    "aws_dynamodb_table", "aws_lambda_function", "aws_iam_role", "aws_iam_policy",
}


@live
def test_web_app_is_approved_and_inventoried(real_settings):
    from app.shadow import run_shadow

    captured = {}

    def shadow(directory):
        captured["result"] = run_shadow(directory)
        return captured["result"]

    cert = analyze_architecture(WEB_APP, use_groq=False, shadow_runner=shadow)
    assert cert["verdict"] == AUTO_APPROVED, cert["blast_radius"]["risk_flags"]
    assert cert["shadow_run"]["applied"] and cert["shadow_run"]["inventory_error"] is None
    found = by_type(cert["shadow_run"]["resources"])
    assert len(found["aws_instance"]) == 2
    # MiniStack also gives each instance its own root volume, which Terraform does not manage,
    # so there are 2 data volumes + 2 root volumes: the inventory shows what really exists.
    assert len(found["aws_ebs_volume"]) == 4
    assert {"aws_db_instance", "aws_lb", "aws_lb_listener", "aws_vpc", "aws_cloudwatch_metric_alarm"} <= set(found)
    # Everything Terraform says it created is really in MiniStack.
    inventory_ids = {r["id"] for r in cert["shadow_run"]["resources"]}
    state = [r for r in captured["result"].resources if r["type"] in INVENTORIED_ID]
    assert state and all(r["id"] in inventory_ids for r in state), [r for r in state if r["id"] not in inventory_ids]
    priced = {r["resource"]: r["monthly_usd"] for r in cert["cost_breakdown"]}
    assert priced["aws_instance.web[0]"] > 0 and priced["aws_db_instance.orders_db"] > 0
    assert 'resource "aws_lb" "front"' in cert["generated_terraform"] and verify(cert)


@live
def test_serverless_prices_usage_from_the_architecture(real_settings):
    cert = analyze_architecture(SERVERLESS, use_groq=False)
    assert cert["verdict"] == AUTO_APPROVED, cert["blast_radius"]["risk_flags"]
    rows = {r["resource"]: r for r in cert["cost_breakdown"]}
    for address, usage_key in [("aws_lambda_function.api", "monthly_requests"),
                               ("aws_dynamodb_table.orders", "monthly_read_request_units"),
                               ("aws_s3_bucket.uploads", "storage_gb")]:
        assert rows[address]["usage_assumptions"][usage_key] > 0
        assert rows[address]["monthly_usd"] > 0, f"{address} should be priced from its usage"
    found = {r["type"] for r in cert["shadow_run"]["resources"]}
    assert {"aws_lambda_function", "aws_dynamodb_table", "aws_s3_bucket", "aws_iam_role", "aws_iam_policy"} <= found


@live
def test_risky_is_blocked_and_its_remediations_fix_it(real_settings):
    cert = analyze_architecture(RISKY, use_groq=False)
    assert cert["verdict"] == BLOCKED
    blocking = [f for f in cert["blast_radius"]["risk_flags"] if f["severity"] in ("CRITICAL", "HIGH")]
    assert {f["rule"] for f in blocking} >= {"GO-SG-001", "GO-S3-001", "GO-IAM-001", "GO-RDS-001", "GO-EXPOSE-001"}
    assert all(f["remediation"]["config_change"] for f in blocking if f["rule"] != "GO-SHADOW-001")

    fixed = apply_config_changes(RISKY, [f["remediation"] for f in cert["blast_radius"]["risk_flags"]])
    ok = ShadowResult(True, "complete", resources=[{"address": "x"}])
    after = analyze_architecture(fixed, use_groq=False, shadow_runner=lambda d: ok, cost_result=NO_COST)
    remaining = [f for f in after["blast_radius"]["risk_flags"] if f["severity"] in ("CRITICAL", "HIGH")]
    assert remaining == [] and after["verdict"] == AUTO_APPROVED


# --- pillar rules on real generated Terraform (terraform plan only, no MiniStack) ---------------------

ADVISORY = {"services": [
    {"type": "ec2", "config": {"name": "web", "instance_type": "m5.xlarge", "expected_cpu_percent": 10}},
    {"type": "s3", "config": {"name": "files", "versioning": False, "encryption": False}},
    {"type": "rds", "config": {"name": "db", "multi_az": False, "backup_retention_days": 0}},
    {"type": "lambda", "config": {"name": "fn", "memory_mb": 128, "timeout_s": 900}},
    {"type": "dynamodb", "config": {"name": "tbl", "billing_mode": "PROVISIONED", "point_in_time_recovery": False}},
]}

ADVISORY_RULES = {
    ("reliability", "GO-REL-001"), ("reliability", "GO-REL-002"), ("reliability", "GO-REL-003"),
    ("reliability", "GO-REL-004"), ("reliability", "GO-REL-005"), ("reliability", "GO-REL-006"),
    ("security", "GO-S3-002"), ("cost", "GO-COST-001"),
    ("performance", "GO-PERF-001"), ("performance", "GO-PERF-002"), ("performance", "GO-PERF-003"),
}


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform missing")
def test_pillar_rules_fire_on_generated_terraform_and_apply_fix_clears_them():
    from app.architecture import check_architecture

    out = check_architecture(ADVISORY, cost_result=NO_COST)
    found = {(f["pillar"], f["rule"]) for f in out["risk_flags"]}
    assert found == ADVISORY_RULES, found ^ ADVISORY_RULES
    assert out["verdict_preview"] == AUTO_APPROVED  # advisory pillars never block
    assert out["pillars"]["security"]["score"] == 95  # one LOW security finding
    assert out["pillars"]["reliability"]["score"] == 100 - 25 - 4 * 10 - 5
    assert out["pillars"]["cost"]["score"] == 90 and out["pillars"]["performance"]["score"] == 75
    # every fix except "add an alarm" is a catalog change that Apply Fix can make
    no_change = {f["rule"] for f in out["risk_flags"] if not f["remediation"]["config_change"]}
    assert no_change == {"GO-REL-006"}

    fixed = apply_config_changes(ADVISORY, [f["remediation"] for f in out["risk_flags"]])
    after = check_architecture(fixed, cost_result=NO_COST)
    assert {f["rule"] for f in after["risk_flags"]} == {"GO-REL-006"}

    fixed["services"].append({"type": "cloudwatch_alarm", "config": {"name": "web-cpu"}})
    clean = check_architecture(fixed, cost_result=NO_COST)
    assert clean["risk_flags"] == []
    assert {p: v["score"] for p, v in clean["pillars"].items()} == {
        "security": 100, "reliability": 100, "cost": 100, "performance": 100}


def test_check_blocks_a_safe_design_that_is_over_budget():
    from app.architecture import check_architecture

    many = {"services": [{"type": "ec2", "config": {"name": f"web-{i}", "count": 10, "instance_type": "m5.xlarge"}}
                         for i in range(1, 6)]}
    expensive = {"monthly_delta_usd": 7128.0, "complete": True, "unpriced": [], "resources": []}
    out = check_architecture(many, planner=plan_stub, cost_result=expensive)
    assert out["verdict_preview"] == BLOCKED
    assert [f["rule"] for f in out["risk_flags"] if f["severity"] == "HIGH"] == ["GO-BUDGET-001"]
    assert not [f for f in out["risk_flags"] if f["pillar"] == "security" and f["severity"] in ("CRITICAL", "HIGH")]
    assert out["pillars"]["cost"]["score"] == 75
    cheap = check_architecture(many, planner=plan_stub, cost_result=NO_COST)
    assert cheap["verdict_preview"] == AUTO_APPROVED
