import json
from pathlib import Path

import pytest

from app.plan_parser import (
    PlanParseError,
    ResourceChange,
    load_plan,
    normalize_action,
    parse_plan,
    parse_plan_json,
)

FIXTURES = Path(__file__).parent / "fixtures"


def by_address(changes: list[ResourceChange]) -> dict[str, ResourceChange]:
    return {c.address: c for c in changes}


# --- real fixtures: demo/bad -------------------------------------------------


def test_bad_plan_lists_every_resource_as_create():
    changes = load_plan(FIXTURES / "bad_plan.json")
    assert sorted(c.address for c in changes) == [
        "aws_iam_policy.admin_star",
        "aws_s3_bucket.public",
        "aws_s3_bucket_acl.public",
        "aws_s3_bucket_ownership_controls.public",
        "aws_s3_bucket_public_access_block.public",
        "aws_security_group.ssh_open",
    ]
    for c in changes:
        assert c.action == "create"
        assert c.raw_actions == ("create",)
        assert c.before is None
        assert isinstance(c.after, dict)
        assert c.provider_name == "registry.terraform.io/hashicorp/aws"


def test_bad_plan_exposes_open_ssh_ingress():
    sg = by_address(load_plan(FIXTURES / "bad_plan.json"))["aws_security_group.ssh_open"]
    assert sg.type == "aws_security_group"
    assert sg.name == "ssh_open"
    ssh_rules = [r for r in sg.after["ingress"] if r["from_port"] == 22 and r["to_port"] == 22]
    assert len(ssh_rules) == 1
    assert ssh_rules[0]["protocol"] == "tcp"
    assert ssh_rules[0]["cidr_blocks"] == ["0.0.0.0/0"]
    # Generated IDs are unknown until apply and must be reported as such.
    assert sg.after_unknown.get("id") is True
    assert "id" not in sg.after


def test_bad_plan_exposes_wildcard_iam_policy():
    pol = by_address(load_plan(FIXTURES / "bad_plan.json"))["aws_iam_policy.admin_star"]
    doc = json.loads(pol.after["policy"])
    assert doc["Statement"] == [{"Action": "*", "Effect": "Allow", "Resource": "*"}]


def test_bad_plan_exposes_public_bucket():
    changes = by_address(load_plan(FIXTURES / "bad_plan.json"))
    acl = changes["aws_s3_bucket_acl.public"]
    assert acl.after["acl"] == "public-read"
    pab = changes["aws_s3_bucket_public_access_block.public"].after
    for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        assert pab[flag] is False, flag


# --- real fixtures: demo/good, every action -----------------------------------


def test_good_plan_creates_tagged_bucket_and_alarm():
    changes = by_address(load_plan(FIXTURES / "good_plan.json"))
    assert set(changes) == {"aws_s3_bucket.logs", "aws_cloudwatch_metric_alarm.bucket_size"}
    assert all(c.action == "create" for c in changes.values())
    assert changes["aws_s3_bucket.logs"].after["tags"] == {
        "CostCenter": "cloud-arch-101",
        "Environment": "dev",
        "Owner": "platform-team",
        "Project": "ghostops",
    }
    alarm = changes["aws_cloudwatch_metric_alarm.bucket_size"].after
    assert alarm["metric_name"] == "BucketSizeBytes"
    assert alarm["threshold"] == 5368709120


def test_noop_plan_reports_unchanged_bucket_as_noop():
    bucket = by_address(load_plan(FIXTURES / "good_noop_plan.json"))["aws_s3_bucket.logs"]
    assert bucket.action == "no-op"
    assert bucket.raw_actions == ("no-op",)
    assert bucket.before == bucket.after
    assert bucket.before["bucket"] == "ghostops-good-logs-bucket"


def test_modified_plan_reports_tag_change_as_update():
    bucket = by_address(load_plan(FIXTURES / "good_modified_plan.json"))["aws_s3_bucket.logs"]
    assert bucket.action == "update"
    assert bucket.before["tags"]["Environment"] == "dev"
    assert bucket.after["tags"]["Environment"] == "prod"
    assert bucket.before["bucket"] == bucket.after["bucket"]


def test_destroy_plan_reports_deletes_with_before_state():
    changes = load_plan(FIXTURES / "good_destroy_plan.json")
    assert {c.address for c in changes} == {"aws_s3_bucket.logs", "aws_cloudwatch_metric_alarm.bucket_size"}
    for c in changes:
        assert c.action == "delete"
        assert c.after is None
        assert isinstance(c.before, dict) and c.before


def test_all_four_actions_covered_by_real_fixtures():
    seen = {c.action for f in FIXTURES.glob("*.json") for c in load_plan(f)}
    assert {"create", "update", "delete", "no-op"} <= seen


# --- action mapping ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (["create"], "create"),
        (["update"], "update"),
        (["delete"], "delete"),
        (["no-op"], "no-op"),
        (["delete", "create"], "replace"),
        (["create", "delete"], "replace"),
    ],
)
def test_normalize_action(raw, expected):
    assert normalize_action(raw) == expected


@pytest.mark.parametrize("raw", [["read"], ["forget"], [], ["update", "delete"], ["create", "create"]])
def test_normalize_action_rejects_unknown(raw):
    with pytest.raises(PlanParseError, match="unsupported Terraform action"):
        normalize_action(raw)


# --- structural handling -----------------------------------------------------


def minimal_plan(*resource_changes):
    return {"format_version": "1.2", "resource_changes": list(resource_changes)}


def rc(address="aws_s3_bucket.x", actions=("create",), mode="managed", before=None, after=None):
    return {
        "address": address,
        "mode": mode,
        "type": address.split(".")[0],
        "name": address.split(".")[1],
        "change": {"actions": list(actions), "before": before, "after": after or {"bucket": "x"}},
    }


def test_replace_in_plan_keeps_before_and_after():
    [c] = parse_plan(minimal_plan(rc(actions=["delete", "create"], before={"bucket": "old"}, after={"bucket": "new"})))
    assert c.action == "replace"
    assert c.raw_actions == ("delete", "create")
    assert c.before == {"bucket": "old"} and c.after == {"bucket": "new"}


def test_data_sources_are_skipped():
    plan = minimal_plan(rc("aws_ami.ubuntu", actions=["read"], mode="data"), rc())
    assert [c.address for c in parse_plan(plan)] == ["aws_s3_bucket.x"]


def test_empty_plan_has_no_changes():
    assert parse_plan({"format_version": "1.2"}) == []


def test_unknown_action_error_names_the_resource():
    with pytest.raises(PlanParseError, match=r"aws_s3_bucket\.x: unsupported"):
        parse_plan(minimal_plan(rc(actions=["forget"])))


@pytest.mark.parametrize(
    ("plan", "message"),
    [
        ([], "must be a JSON object"),
        ({}, "missing format_version"),
        ({"format_version": "2.0"}, "unsupported plan format_version"),
        ({"format_version": "1.2", "resource_changes": {}}, "must be a list"),
        (minimal_plan({"type": "aws_s3_bucket", "change": {"actions": ["create"]}}), "no address"),
        (minimal_plan({"address": "a.b", "change": {"actions": ["create"]}}), "missing type"),
        (minimal_plan({"address": "a.b", "type": "a"}), "missing change.actions"),
        (minimal_plan({"address": "a.b", "type": "a", "change": {"actions": ["create"], "after": "x"}}),
         "change.after must be an object"),
    ],
)
def test_rejects_malformed_plans(plan, message):
    with pytest.raises(PlanParseError, match=message):
        parse_plan(plan)


def test_invalid_json_raises_parse_error():
    with pytest.raises(PlanParseError, match="invalid JSON"):
        parse_plan_json("{not json")


def test_reads_utf16_file_from_powershell_redirect(tmp_path):
    # Windows PowerShell 5.1 `terraform show -json p > plan.json` writes UTF-16 LE with BOM.
    text = (FIXTURES / "good_plan.json").read_text(encoding="utf-8")
    path = tmp_path / "plan.json"
    path.write_bytes(text.encode("utf-16"))
    assert len(load_plan(path)) == 2
