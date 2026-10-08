# Pillar rules (advisory, in `warn`). Each rule has a test that it fires and one that
# it stays quiet on a clean config; a whole clean architecture triggers nothing.
# Shares plan/create/ids helpers with ghostops_test.rego. Run: opa test rules tests/rego -v
package ghostops_test

import data.ghostops

named(type, name, after) := {
	"address": sprintf("%s.%s", [type, name]),
	"mode": "managed", "type": type, "name": name,
	"change": {"actions": ["create"], "before": null, "after": after},
}

warn_ids(changes) := found if {
	found := ids(ghostops.warn) with input as plan(changes)
}

fires(rule, changes) if rule in warn_ids(changes)

quiet(rule, changes) if not rule in warn_ids(changes)

tags := {"Name": "x", "Owner": "team"}

clean_rds := {"storage_encrypted": true, "multi_az": true, "backup_retention_period": 7, "tags": tags}

clean_lambda := {"memory_size": 256, "timeout": 30, "tags": tags}

clean_table := {"name": "t", "billing_mode": "PAY_PER_REQUEST", "point_in_time_recovery": [{"enabled": true}], "tags": tags}

provisioned := object.union(clean_table, {"billing_mode": "PROVISIONED", "read_capacity": 5, "write_capacity": 5})

bucket(name) := named("aws_s3_bucket", name, {"bucket": name, "tags": tags})

versioning(name, status) := named("aws_s3_bucket_versioning", name, {"bucket": name, "versioning_configuration": [{"status": status}]})

sse(name) := named("aws_s3_bucket_server_side_encryption_configuration", name, {
	"bucket": name,
	"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
})

alarm := named("aws_cloudwatch_metric_alarm", "cpu", {"alarm_name": "cpu"})

instance(name, type, extra_tags) := named("aws_instance", name, {"instance_type": type, "tags": object.union(tags, extra_tags)})

# --- GO-REL-001 RDS Multi-AZ -------------------------------------------------

test_rel_001_fires_when_multi_az_false if fires("GO-REL-001", [create("aws_db_instance", object.union(clean_rds, {"multi_az": false})), alarm])

test_rel_001_fires_when_multi_az_unset if fires("GO-REL-001", [create("aws_db_instance", object.remove(clean_rds, ["multi_az"])), alarm])

test_rel_001_quiet_when_multi_az if quiet("GO-REL-001", [create("aws_db_instance", clean_rds), alarm])

# --- GO-REL-002 RDS backups --------------------------------------------------

test_rel_002_fires_when_retention_zero if {
	findings := ghostops.warn with input as plan([create("aws_db_instance", object.union(clean_rds, {"backup_retention_period": 0})), alarm])
	some f in findings
	f.rule_id == "GO-REL-002"
	f.severity == "HIGH"
	f.pillar == "reliability"
}

test_rel_002_quiet_with_retention if quiet("GO-REL-002", [create("aws_db_instance", clean_rds), alarm])

test_rel_002_is_advisory_not_deny if {
	count(ghostops.deny) == 0 with input as plan([create("aws_db_instance", object.union(clean_rds, {"backup_retention_period": 0}))])
}

# --- GO-REL-003 S3 versioning ------------------------------------------------

test_rel_003_fires_without_versioning if fires("GO-REL-003", [bucket("b"), sse("b")])

test_rel_003_fires_when_versioning_suspended if fires("GO-REL-003", [bucket("b"), versioning("b", "Suspended"), sse("b")])

test_rel_003_fires_when_versioning_is_for_another_bucket if fires("GO-REL-003", [bucket("b"), versioning("other", "Enabled"), sse("b")])

test_rel_003_quiet_with_versioning if quiet("GO-REL-003", [bucket("b"), versioning("b", "Enabled"), sse("b")])

# The usual form, `bucket = aws_s3_bucket.b.id`, is unknown in the plan, so the
# link comes from the configuration references.
test_rel_003_quiet_with_versioning_linked_by_reference if {
	v := named("aws_s3_bucket_versioning", "v", {"versioning_configuration": [{"status": "Enabled"}]})
	cfg := {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.v",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
	}]}}
	not "GO-REL-003" in ids(ghostops.warn) with input as {"format_version": "1.2", "resource_changes": [bucket("b"), v, sse("b")], "configuration": cfg}
}

# --- GO-S3-002 S3 encryption (security, LOW) ---------------------------------

test_s3_002_fires_without_encryption if {
	findings := ghostops.warn with input as plan([bucket("b"), versioning("b", "Enabled")])
	some f in findings
	f.rule_id == "GO-S3-002"
	f.pillar == "security"
	f.severity == "LOW"
}

test_s3_002_quiet_with_encryption if quiet("GO-S3-002", [bucket("b"), versioning("b", "Enabled"), sse("b")])

# --- GO-REL-004 single EC2 without a load balancer ---------------------------

test_rel_004_fires_for_single_instance if fires("GO-REL-004", [instance("web", "t3.micro", {}), alarm])

test_rel_004_quiet_with_two_instances if quiet("GO-REL-004", [instance("a", "t3.micro", {}), instance("b", "t3.micro", {}), alarm])

test_rel_004_quiet_behind_load_balancer if quiet("GO-REL-004", [instance("web", "t3.micro", {}), named("aws_lb", "lb", {"tags": tags}), alarm])

# --- GO-REL-005 DynamoDB PITR ------------------------------------------------

test_rel_005_fires_without_pitr if fires("GO-REL-005", [create("aws_dynamodb_table", object.union(clean_table, {"point_in_time_recovery": [{"enabled": false}]})), alarm])

test_rel_005_quiet_with_pitr if quiet("GO-REL-005", [create("aws_dynamodb_table", clean_table), alarm])

# --- GO-REL-006 no alarm -----------------------------------------------------

test_rel_006_fires_once_without_alarm if {
	findings := ghostops.warn with input as plan([instance("a", "t3.micro", {}), instance("b", "t3.micro", {})])
	matched := [f | some f in findings; f.rule_id == "GO-REL-006"]
	count(matched) == 1
	matched[0].address == "aws_instance.a"
}

test_rel_006_quiet_with_alarm if quiet("GO-REL-006", [instance("a", "t3.micro", {}), alarm])

test_rel_006_existing_alarm_counts if {
	existing := object.union(alarm, {"change": {"actions": ["no-op"], "before": {}, "after": {"alarm_name": "cpu"}}})
	quiet("GO-REL-006", [instance("a", "t3.micro", {}), existing])
}

# --- GO-COST-001 oversized EC2 -----------------------------------------------

test_cost_001_fires_for_large_instance_at_low_cpu if fires("GO-COST-001", [instance("web", "m5.xlarge", {"ExpectedCpuPercent": "10"}), alarm])

test_cost_001_quiet_for_small_instance if quiet("GO-COST-001", [instance("web", "t3.small", {"ExpectedCpuPercent": "10"}), alarm])

test_cost_001_quiet_when_usage_is_high if quiet("GO-COST-001", [instance("web", "m5.xlarge", {"ExpectedCpuPercent": "70"}), alarm])

test_cost_001_quiet_without_stated_usage if quiet("GO-COST-001", [instance("web", "m5.xlarge", {}), alarm])

# --- GO-COST-002 gp2 ---------------------------------------------------------

test_cost_002_fires_for_gp2_volume if fires("GO-COST-002", [create("aws_ebs_volume", {"type": "gp2", "tags": tags})])

test_cost_002_fires_for_gp2_rds if fires("GO-COST-002", [create("aws_db_instance", object.union(clean_rds, {"storage_type": "gp2"})), alarm])

test_cost_002_quiet_for_gp3 if quiet("GO-COST-002", [create("aws_ebs_volume", {"type": "gp3", "tags": tags})])

# --- GO-COST-003 missing tags ------------------------------------------------

test_cost_003_fires_without_tags if fires("GO-COST-003", [create("aws_ebs_volume", {"type": "gp3"})])

test_cost_003_fires_with_empty_tags if fires("GO-COST-003", [create("aws_ebs_volume", {"type": "gp3", "tags": {}})])

test_cost_003_quiet_with_tags if quiet("GO-COST-003", [create("aws_ebs_volume", {"type": "gp3", "tags": tags})])

test_cost_003_quiet_with_provider_default_tags if quiet("GO-COST-003", [create("aws_ebs_volume", {"type": "gp3", "tags": null, "tags_all": tags})])

# --- GO-PERF-001 Lambda memory -----------------------------------------------

test_perf_001_fires_at_128_mb if fires("GO-PERF-001", [create("aws_lambda_function", object.union(clean_lambda, {"memory_size": 128})), alarm])

test_perf_001_quiet_at_256_mb if quiet("GO-PERF-001", [create("aws_lambda_function", clean_lambda), alarm])

# --- GO-PERF-002 Lambda timeout ----------------------------------------------

test_perf_002_fires_at_max_timeout if fires("GO-PERF-002", [create("aws_lambda_function", object.union(clean_lambda, {"timeout": 900})), alarm])

test_perf_002_quiet_with_short_timeout if quiet("GO-PERF-002", [create("aws_lambda_function", clean_lambda), alarm])

# --- GO-PERF-003 DynamoDB provisioned without auto scaling --------------------

test_perf_003_fires_for_provisioned_table if fires("GO-PERF-003", [create("aws_dynamodb_table", provisioned), alarm])

test_perf_003_quiet_with_autoscaling if {
	target := named("aws_appautoscaling_target", "read", {"service_namespace": "dynamodb", "resource_id": "table/t"})
	quiet("GO-PERF-003", [create("aws_dynamodb_table", provisioned), target, alarm])
}

test_perf_003_quiet_on_demand if quiet("GO-PERF-003", [create("aws_dynamodb_table", clean_table), alarm])

# --- a clean architecture triggers nothing -----------------------------------

clean_architecture := [
	instance("a", "t3.small", {"ExpectedCpuPercent": "10"}),
	instance("b", "t3.small", {"ExpectedCpuPercent": "10"}),
	named("aws_lb", "lb", {"tags": tags}),
	create("aws_db_instance", clean_rds),
	bucket("b"), versioning("b", "Enabled"), sse("b"),
	create("aws_dynamodb_table", clean_table),
	create("aws_lambda_function", clean_lambda),
	create("aws_ebs_volume", {"type": "gp3", "tags": tags}),
	alarm,
]

test_clean_architecture_has_no_findings if {
	count(ghostops.warn) == 0 with input as plan(clean_architecture)
	count(ghostops.deny) == 0 with input as plan(clean_architecture)
}

test_advisory_pillars_never_deny if {
	findings := ghostops.deny with input as plan([
		instance("web", "m5.xlarge", {"ExpectedCpuPercent": "5"}),
		create("aws_db_instance", {"storage_encrypted": true, "backup_retention_period": 0}),
		bucket("b"),
		create("aws_lambda_function", {"timeout": 900}),
		create("aws_dynamodb_table", provisioned),
	])
	count(findings) == 0
}

test_every_finding_has_a_known_pillar if {
	findings := ghostops.warn with input as plan([
		instance("web", "m5.xlarge", {"ExpectedCpuPercent": "5"}),
		create("aws_db_instance", {"storage_encrypted": true, "backup_retention_period": 0}),
		bucket("b"),
		create("aws_lambda_function", {"timeout": 900}),
	])
	count(findings) > 5
	every f in findings { f.pillar in {"security", "reliability", "cost", "performance"} }
}
