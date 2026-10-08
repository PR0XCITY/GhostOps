# Unit tests for backend/rules. Run from backend/:  opa test rules tests/rego -v
package ghostops_test

import data.ghostops

plan(changes) := {"format_version": "1.2", "resource_changes": changes}

rc(type, actions, after) := {
	"address": sprintf("%s.t", [type]),
	"mode": "managed",
	"type": type,
	"name": "t",
	"change": {"actions": actions, "before": null, "after": after},
}

create(type, after) := rc(type, ["create"], after)

ids(findings) := {f.rule_id | some f in findings}

sg(rules) := create("aws_security_group", {"ingress": rules})

ingress(protocol, from, to, v4, v6) := {
	"protocol": protocol, "from_port": from, "to_port": to,
	"cidr_blocks": v4, "ipv6_cidr_blocks": v6,
}

policy(statement) := create("aws_iam_policy", {"policy": json.marshal({"Version": "2012-10-17", "Statement": statement})})

# --- GO-SG-001 ---------------------------------------------------------------

test_sg_ssh_from_ipv4_world if {
	findings := ghostops.deny with input as plan([sg([ingress("tcp", 22, 22, ["0.0.0.0/0"], [])])])
	count(findings) == 1
	some f in findings
	f.rule_id == "GO-SG-001"
	f.severity == "CRITICAL"
	f.address == "aws_security_group.t"
	contains(f.message, "SSH (port 22)")
}

test_sg_rdp_from_ipv6_world if {
	findings := ghostops.deny with input as plan([sg([ingress("tcp", 3389, 3389, [], ["::/0"])])])
	some f in findings
	contains(f.message, "RDP (port 3389) from ::/0")
}

test_sg_port_range_covering_both_ports if {
	findings := ghostops.deny with input as plan([sg([ingress("tcp", 0, 65535, ["0.0.0.0/0"], [])])])
	count(findings) == 2
}

test_sg_all_traffic_protocol if {
	findings := ghostops.deny with input as plan([sg([ingress("-1", 0, 0, ["0.0.0.0/0"], [])])])
	count(findings) == 2
}

test_sg_ssh_from_private_range_is_fine if {
	count(ghostops.deny) == 0 with input as plan([sg([ingress("tcp", 22, 22, ["10.0.0.0/8"], [])])])
}

test_sg_https_from_world_is_fine if {
	count(ghostops.deny) == 0 with input as plan([sg([ingress("tcp", 443, 443, ["0.0.0.0/0"], ["::/0"])])])
}

test_sg_udp_22_is_fine if {
	count(ghostops.deny) == 0 with input as plan([sg([ingress("udp", 22, 22, ["0.0.0.0/0"], [])])])
}

test_sg_rule_resource_ingress if {
	r := create("aws_security_group_rule", object.union(ingress("tcp", 22, 22, ["0.0.0.0/0"], null), {"type": "ingress"}))
	ids(ghostops.deny) == {"GO-SG-001"} with input as plan([r])
}

test_sg_rule_resource_egress_is_fine if {
	r := create("aws_security_group_rule", object.union(ingress("tcp", 22, 22, ["0.0.0.0/0"], null), {"type": "egress"}))
	count(ghostops.deny) == 0 with input as plan([r])
}

test_vpc_ingress_rule_resource if {
	r := create("aws_vpc_security_group_ingress_rule", {"ip_protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ipv4": "0.0.0.0/0"})
	ids(ghostops.deny) == {"GO-SG-001"} with input as plan([r])
}

test_unchanged_resource_is_not_judged if {
	r := rc("aws_security_group", ["no-op"], {"ingress": [ingress("tcp", 22, 22, ["0.0.0.0/0"], [])]})
	count(ghostops.deny) == 0 with input as plan([r])
}

# --- GO-IAM-001 --------------------------------------------------------------

test_iam_star_star_strings if {
	findings := ghostops.deny with input as plan([policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])])
	some f in findings
	f.rule_id == "GO-IAM-001"
	f.severity == "CRITICAL"
}

test_iam_star_in_lists_and_single_statement_object if {
	p := policy({"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]})
	ids(ghostops.deny) == {"GO-IAM-001"} with input as plan([p])
}

test_iam_inline_role_policy if {
	r := create("aws_iam_role_policy", {"policy": json.marshal({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})})
	ids(ghostops.deny) == {"GO-IAM-001"} with input as plan([r])
}

test_iam_deny_star_is_fine if {
	count(ghostops.deny) == 0 with input as plan([policy([{"Effect": "Deny", "Action": "*", "Resource": "*"}])])
}

test_iam_service_wildcard_is_fine if {
	count(ghostops.deny) == 0 with input as plan([policy([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])])
}

test_iam_star_on_one_resource_is_fine if {
	p := policy([{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}])
	count(ghostops.deny) == 0 with input as plan([p])
}

# --- GO-S3-001 ---------------------------------------------------------------

test_s3_public_read_write_acl if {
	findings := ghostops.deny with input as plan([create("aws_s3_bucket_acl", {"acl": "public-read-write"})])
	some f in findings
	f.rule_id == "GO-S3-001"
	f.severity == "HIGH"
	contains(f.message, "read and overwrite")
}

test_s3_legacy_bucket_acl_argument if {
	ids(ghostops.deny) == {"GO-S3-001"} with input as plan([create("aws_s3_bucket", {"bucket": "b", "acl": "public-read"})])
}

test_s3_private_acl_is_fine if {
	count(ghostops.deny) == 0 with input as plan([create("aws_s3_bucket_acl", {"acl": "private"})])
}

# --- GO-RDS-001 --------------------------------------------------------------

test_rds_encryption_false if {
	findings := ghostops.deny with input as plan([create("aws_db_instance", {"storage_encrypted": false})])
	some f in findings
	f.rule_id == "GO-RDS-001"
	f.severity == "HIGH"
}

test_rds_encryption_missing_fails_closed if {
	ids(ghostops.deny) == {"GO-RDS-001"} with input as plan([create("aws_db_instance", {"engine": "postgres"})])
}

test_rds_encrypted_is_fine if {
	count(ghostops.deny) == 0 with input as plan([create("aws_db_instance", {"storage_encrypted": true})])
}

# --- GO-DEL-001 --------------------------------------------------------------

test_delete_warns if {
	findings := ghostops.warn with input as plan([rc("aws_s3_bucket", ["delete"], null)])
	some f in findings
	f.rule_id == "GO-DEL-001"
	f.severity == "MEDIUM"
	contains(f.message, "will be destroyed")
}

test_replace_warns_as_replacement if {
	findings := ghostops.warn with input as plan([rc("aws_s3_bucket", ["delete", "create"], {"bucket": "b"})])
	some f in findings
	contains(f.message, "replaced (destroyed and re-created)")
}

test_update_does_not_warn_about_deletion if {
	not "GO-DEL-001" in ids(ghostops.warn) with input as plan([rc("aws_s3_bucket", ["update"], {"bucket": "b"})])
}

test_deletion_is_reliability_pillar if {
	some f in ghostops.warn with input as plan([rc("aws_s3_bucket", ["delete"], null)])
	f.pillar == "reliability"
}

test_original_rules_are_security_pillar if {
	findings := ghostops.deny with input as plan([create("aws_db_instance", {"storage_encrypted": false})])
	count(findings) > 0
	every f in findings { f.pillar == "security" }
}

test_data_source_read_is_ignored if {
	r := object.union(rc("aws_s3_bucket", ["read"], {"acl": "public-read"}), {"mode": "data"})
	count(ghostops.deny) + count(ghostops.warn) == 0 with input as plan([r])
}
