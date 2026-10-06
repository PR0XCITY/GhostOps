import json
from pathlib import Path

import pytest

from app.blast_radius import analyze, analyze_file, build_graph, config_edges
from app.plan_parser import PlanParseError, parse_plan

FIXTURES = Path(__file__).parent / "fixtures"


def addresses(entries):
    return [e["address"] for e in entries]


def node_risks(report):
    return {n["id"]: set(n["risk_reasons"]) for n in report["graph"]["nodes"]}


def edges(report):
    return {(e["source"], e["target"], tuple(e["via"])) for e in report["graph"]["edges"]}


# --- demo/bad -------------------------------------------------------------------


@pytest.fixture(scope="module")
def bad():
    return analyze_file(FIXTURES / "bad_plan.json")


def test_bad_newly_public_includes_blast_radius(bad):
    assert bad["newly_public"] == [
        {"address": "aws_instance.web", "type": "aws_instance", "via": ["aws_security_group.ssh_open"]},
        {"address": "aws_s3_bucket.public", "type": "aws_s3_bucket", "via": ["aws_s3_bucket_acl.public"]},
        {"address": "aws_security_group.ssh_open", "type": "aws_security_group",
         "via": ["aws_security_group.ssh_open"]},
    ]


def test_bad_iam_widened_to_admin(bad):
    assert bad["iam_widened"] == [{
        "address": "aws_iam_policy.admin_star", "type": "aws_iam_policy",
        "added_grants": [{"action": "*", "resource": "*"}], "removed_denies": [],
        "admin": True, "unknown": False,
    }]


def test_bad_created_and_destroyed(bad):
    assert len(bad["created"]) == 8
    assert "aws_db_instance.unencrypted" in addresses(bad["created"])
    assert bad["destroyed"] == []


def test_bad_graph_edges_from_config_references(bad):
    assert edges(bad) == {
        ("aws_instance.web", "aws_security_group.ssh_open", ("vpc_security_group_ids",)),
        ("aws_s3_bucket_acl.public", "aws_s3_bucket.public", ("bucket",)),
        ("aws_s3_bucket_acl.public", "aws_s3_bucket_ownership_controls.public", ("depends_on",)),
        ("aws_s3_bucket_acl.public", "aws_s3_bucket_public_access_block.public", ("depends_on",)),
        ("aws_s3_bucket_ownership_controls.public", "aws_s3_bucket.public", ("bucket",)),
        ("aws_s3_bucket_public_access_block.public", "aws_s3_bucket.public", ("bucket",)),
    }
    assert bad["edges_added"] and bad["edges_removed"] == []


def test_bad_graph_risk_flags(bad):
    assert node_risks(bad) == {
        "aws_db_instance.unencrypted": set(),  # not attached to anything public
        "aws_iam_policy.admin_star": {"iam_widened", "iam_admin"},
        "aws_instance.web": {"public_exposure"},
        "aws_s3_bucket.public": {"public_exposure"},
        "aws_s3_bucket_acl.public": {"opens_public_access"},
        "aws_s3_bucket_ownership_controls.public": set(),
        "aws_s3_bucket_public_access_block.public": set(),
        "aws_security_group.ssh_open": {"public_exposure", "opens_public_access"},
    }
    for node in bad["graph"]["nodes"]:
        assert node["risk"] is bool(node["risk_reasons"])


def test_graph_export_is_plain_json(bad):
    assert json.loads(json.dumps(bad["graph"])) == bad["graph"]
    assert set(bad["graph"]["nodes"][0]) == {"id", "type", "action", "risk", "risk_reasons"}


# --- demo/good ------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["good_plan.json", "good_noop_plan.json", "good_modified_plan.json"])
def test_good_has_no_exposure_or_iam_widening(fixture):
    report = analyze_file(FIXTURES / fixture)
    assert report["newly_public"] == []
    assert report["iam_widened"] == []
    assert not any(n["risk"] for n in report["graph"]["nodes"])
    assert ("aws_cloudwatch_metric_alarm.bucket_size", "aws_s3_bucket.logs", ("dimensions",)) in edges(report)


def test_good_plan_creates_two():
    report = analyze_file(FIXTURES / "good_plan.json")
    assert addresses(report["created"]) == ["aws_cloudwatch_metric_alarm.bucket_size", "aws_s3_bucket.logs"]
    assert report["destroyed"] == []


def test_good_destroy_plan():
    report = analyze_file(FIXTURES / "good_destroy_plan.json")
    assert addresses(report["destroyed"]) == ["aws_cloudwatch_metric_alarm.bucket_size", "aws_s3_bucket.logs"]
    assert report["created"] == []
    assert report["graph"] == {"nodes": [], "edges": []}


# --- synthetic plans: existing infrastructure changing -----------------------------


def rc(address, actions, before, after, after_unknown=None):
    return {
        "address": address, "mode": "managed",
        "type": address.split(".")[0], "name": address.split(".")[1].split("[")[0],
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": after_unknown or {}},
    }


def plan(*changes, configuration=None):
    p = {"format_version": "1.2", "resource_changes": list(changes)}
    if configuration:
        p["configuration"] = configuration
    return p


def sg(cidrs, sg_id="sg-1"):
    return {"id": sg_id, "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443,
                                       "cidr_blocks": cidrs, "ipv6_cidr_blocks": []}]}


INSTANCE = {"id": "i-1", "vpc_security_group_ids": ["sg-1"]}


def test_opening_existing_sg_exposes_attached_instance():
    report = analyze(plan(
        rc("aws_security_group.web", ["update"], sg(["10.0.0.0/8"]), sg(["0.0.0.0/0"])),
        rc("aws_instance.app", ["no-op"], INSTANCE, INSTANCE),
    ))
    assert addresses(report["newly_public"]) == ["aws_instance.app", "aws_security_group.web"]
    assert report["created"] == [] and report["destroyed"] == []
    # edge found by value matching (instance lists the SG's id), present in both graphs
    assert ("aws_instance.app", "aws_security_group.web", ("vpc_security_group_ids",)) in edges(report)
    assert report["edges_added"] == []


def test_already_public_is_not_newly_public():
    report = analyze(plan(
        rc("aws_security_group.web", ["update"], sg(["0.0.0.0/0"]), sg(["0.0.0.0/0", "10.0.0.0/8"])),
        rc("aws_instance.app", ["no-op"], INSTANCE, INSTANCE),
    ))
    assert report["newly_public"] == []
    assert node_risks(report)["aws_instance.app"] == {"public_exposure"}  # still flagged in the graph


def test_closing_sg_removes_exposure():
    report = analyze(plan(rc("aws_security_group.web", ["update"], sg(["0.0.0.0/0"]), sg(["10.0.0.0/8"]))))
    assert report["newly_public"] == []
    assert node_risks(report)["aws_security_group.web"] == set()


def test_ipv6_world_counts():
    report = analyze(plan(rc("aws_security_group.web", ["create"], None,
                             {"ingress": [{"protocol": "tcp", "from_port": 80, "to_port": 80,
                                           "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}]})))
    assert addresses(report["newly_public"]) == ["aws_security_group.web"]


def test_sg_rule_resource_opens_its_group_but_not_its_source_group():
    rule = {"id": "sgr-1", "type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"], "security_group_id": "sg-1"}
    peer_rule = {"id": "sgr-2", "type": "ingress", "protocol": "tcp", "from_port": 5432, "to_port": 5432,
                 "security_group_id": "sg-2", "source_security_group_id": "sg-1"}
    report = analyze(plan(
        rc("aws_security_group.web", ["no-op"], {"id": "sg-1", "ingress": []}, {"id": "sg-1", "ingress": []}),
        rc("aws_security_group.db", ["no-op"], {"id": "sg-2", "ingress": []}, {"id": "sg-2", "ingress": []}),
        rc("aws_security_group_rule.ssh", ["create"], None, rule),
        rc("aws_security_group_rule.db_from_web", ["create"], None, peer_rule),
        rc("aws_instance.app", ["no-op"], INSTANCE, INSTANCE),
    ))
    assert addresses(report["newly_public"]) == ["aws_instance.app", "aws_security_group.web"]
    assert node_risks(report)["aws_security_group_rule.ssh"] == {"opens_public_access"}
    assert node_risks(report)["aws_security_group.db"] == set()


@pytest.mark.parametrize(("publicly_accessible", "exposed"), [(False, False), (True, True)])
def test_rds_only_public_when_publicly_accessible(publicly_accessible, exposed):
    db = {"id": "db-1", "vpc_security_group_ids": ["sg-1"], "publicly_accessible": publicly_accessible}
    report = analyze(plan(
        rc("aws_security_group.web", ["update"], sg(["10.0.0.0/8"]), sg(["0.0.0.0/0"])),
        rc("aws_db_instance.main", ["no-op"], db, db),
    ))
    assert ("aws_db_instance.main" in addresses(report["newly_public"])) is exposed


BUCKET = {"id": "b", "bucket": "b"}


def bucket_plan(*extra):
    return plan(rc("aws_s3_bucket.b", ["no-op"], BUCKET, BUCKET),
                rc("aws_s3_bucket_acl.b", ["update"], {"id": "b,private", "bucket": "b", "acl": "private"},
                   {"id": "b,public-read", "bucket": "b", "acl": "public-read"}),
                *extra)


def test_public_acl_on_existing_bucket():
    assert addresses(analyze(bucket_plan())["newly_public"]) == ["aws_s3_bucket.b"]


def test_public_access_block_ignoring_acls_neutralizes_acl():
    pab = {"id": "b", "bucket": "b", "ignore_public_acls": True, "restrict_public_buckets": False}
    assert analyze(bucket_plan(rc("aws_s3_bucket_public_access_block.b", ["no-op"], pab, pab)))["newly_public"] == []


def test_bucket_owner_enforced_disables_acls():
    oc = {"id": "b", "bucket": "b", "rule": [{"object_ownership": "BucketOwnerEnforced"}]}
    assert analyze(bucket_plan(rc("aws_s3_bucket_ownership_controls.b", ["no-op"], oc, oc)))["newly_public"] == []


def bucket_policy(principal):
    return json.dumps({"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject",
                                      "Resource": "arn:aws:s3:::b/*"}]})


@pytest.mark.parametrize(("principal", "restrict", "exposed"), [
    ("*", False, True), ({"AWS": "*"}, False, True), ({"AWS": "arn:aws:iam::1:root"}, False, False), ("*", True, False),
])
def test_bucket_policy_principal_star(principal, restrict, exposed):
    pab = {"id": "b", "bucket": "b", "ignore_public_acls": False, "restrict_public_buckets": restrict}
    report = analyze(plan(
        rc("aws_s3_bucket.b", ["no-op"], BUCKET, BUCKET),
        rc("aws_s3_bucket_policy.b", ["create"], None, {"bucket": "b", "policy": bucket_policy(principal)}),
        rc("aws_s3_bucket_public_access_block.b", ["no-op"], pab, pab),
    ))
    assert (addresses(report["newly_public"]) == ["aws_s3_bucket.b"]) is exposed


# --- IAM widening ---------------------------------------------------------------


def policy(*statements):
    return {"policy": json.dumps({"Version": "2012-10-17", "Statement": list(statements)})}


READ = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
S3_ALL = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}


def test_policy_update_that_adds_permissions():
    [entry] = analyze(plan(rc("aws_iam_policy.p", ["update"], policy(READ), policy(READ, S3_ALL))))["iam_widened"]
    assert entry["added_grants"] == [{"action": "s3:*", "resource": "*"}]
    assert entry["admin"] is False


def test_policy_update_that_narrows_is_not_widened():
    assert analyze(plan(rc("aws_iam_policy.p", ["update"], policy(S3_ALL), policy(READ))))["iam_widened"] == []


def test_wildcard_before_covers_specific_after():
    report = analyze(plan(rc("aws_iam_policy.p", ["update"], policy(S3_ALL),
                             policy({"Effect": "Allow", "Action": ["S3:PutObject"], "Resource": "arn:aws:s3:::x"}))))
    assert report["iam_widened"] == []  # actions are case-insensitive and covered by s3:*


def test_not_action_counts_as_everything():
    [entry] = analyze(plan(rc("aws_iam_policy.p", ["create"], None,
                              policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))))["iam_widened"]
    assert entry["admin"] is True


def test_removing_a_deny_is_widening():
    deny = {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}
    [entry] = analyze(plan(rc("aws_iam_role_policy.p", ["update"], policy(READ, deny), policy(READ))))["iam_widened"]
    assert entry["removed_denies"] == [{"action": "s3:deletebucket", "resource": "*"}]
    assert entry["added_grants"] == []


def test_policy_unknown_until_apply_fails_closed():
    [entry] = analyze(plan(rc("aws_iam_policy.p", ["create"], None, {}, after_unknown={"policy": True})))["iam_widened"]
    assert entry["unknown"] is True


def test_admin_managed_policy_attachment():
    att = {"role": "app", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    [entry] = analyze(plan(rc("aws_iam_role_policy_attachment.a", ["create"], None, att)))["iam_widened"]
    assert entry["admin"] is True
    readonly = {"role": "app", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
    assert analyze(plan(rc("aws_iam_role_policy_attachment.a", ["create"], None, readonly)))["iam_widened"] == []


# --- graph mechanics ------------------------------------------------------------


def test_shared_ids_link_sub_resources_to_their_bucket_only():
    pab = {"id": "b", "bucket": "b", "ignore_public_acls": False, "restrict_public_buckets": False}
    oc = {"id": "b", "bucket": "b", "rule": [{"object_ownership": "BucketOwnerPreferred"}]}
    report = analyze(plan(
        rc("aws_s3_bucket.b", ["no-op"], BUCKET, BUCKET),
        rc("aws_s3_bucket_public_access_block.b", ["no-op"], pab, pab),
        rc("aws_s3_bucket_ownership_controls.b", ["no-op"], oc, oc),
    ))
    assert {(e["source"], e["target"]) for e in report["graph"]["edges"]} == {
        ("aws_s3_bucket_public_access_block.b", "aws_s3_bucket.b"),
        ("aws_s3_bucket_ownership_controls.b", "aws_s3_bucket.b"),
    }


def test_replace_is_both_created_and_destroyed():
    report = analyze(plan(rc("aws_s3_bucket.b", ["delete", "create"], BUCKET, {"bucket": "b2"})))
    assert addresses(report["created"]) == addresses(report["destroyed"]) == ["aws_s3_bucket.b"]


def test_config_references_cover_modules_counts_and_skip_non_resources():
    configuration = {"root_module": {
        "resources": [{"address": "aws_instance.app", "mode": "managed", "expressions": {
            "vpc_security_group_ids": {"references": ["aws_security_group.web[0].id", "aws_security_group.web",
                                                      "var.extra_sg", "data.aws_vpc.main.id"]},
            "ebs_block_device": [{"kms_key_id": {"references": ["aws_kms_key.k.arn", "aws_kms_key.k"]}}],
            "ami": {"constant_value": {"references": ["aws_ami.not_a_reference"]}},
        }}],
        "module_calls": {"net": {"module": {"resources": [
            {"address": "aws_subnet.a", "mode": "managed",
             "expressions": {"vpc_id": {"references": ["aws_vpc.main.id"]}}},
        ]}}},
    }}
    p = {"format_version": "1.2", "resource_changes": [], "configuration": configuration}
    assert sorted(set(config_edges(p))) == [
        ("aws_instance.app", "aws_kms_key.k", "ebs_block_device"),
        ("aws_instance.app", "aws_security_group.web", "vpc_security_group_ids"),
        ("module.net.aws_subnet.a", "module.net.aws_vpc.main", "vpc_id"),
    ]

    # instance-less config addresses map onto every instance in the plan
    changes = parse_plan(plan(rc("aws_instance.app[0]", ["create"], None, {}),
                              rc("aws_instance.app[1]", ["create"], None, {}),
                              rc("aws_security_group.web[0]", ["create"], None, {})))
    graph = build_graph(changes, "after", config_edges(p))
    assert set(graph.edges) == {("aws_instance.app[0]", "aws_security_group.web[0]"),
                                ("aws_instance.app[1]", "aws_security_group.web[0]")}


def test_invalid_input():
    with pytest.raises(PlanParseError):
        analyze({"resource_changes": []})
    with pytest.raises(ValueError):
        build_graph([], "during")
