# Reliability pillar (advisory: warn, never blocks).
#
# GO-REL-001 MEDIUM  RDS instance not Multi-AZ (unset counts as off: the AWS default).
# GO-REL-002 HIGH    RDS automated backups disabled (backup_retention_period = 0).
# GO-REL-003 MEDIUM  S3 bucket without versioning.
# GO-REL-004 MEDIUM  A single EC2 instance and no load balancer or auto scaling group.
# GO-REL-005 MEDIUM  DynamoDB table without point-in-time recovery.
# GO-REL-006 LOW     Compute or data resources created with no CloudWatch alarm in the plan.
package ghostops

warn contains f if {
	some rc in changed
	rc.type == "aws_db_instance"
	not after_value(rc, "multi_az", null) == true
	f := pfinding(
		"GO-REL-001", "reliability", "MEDIUM", rc.address,
		sprintf("%s is not Multi-AZ: if its availability zone fails, the database is down until it is restored.", [rc.address]),
	)
}

warn contains f if {
	some rc in changed
	rc.type == "aws_db_instance"
	after_value(rc, "backup_retention_period", null) == 0
	f := pfinding(
		"GO-REL-002", "reliability", "HIGH", rc.address,
		sprintf("%s has automated backups turned off (backup_retention_period = 0): no point-in-time restore is possible.", [rc.address]),
	)
}

versioned(bucket) if {
	some v in after_state
	v.type == "aws_s3_bucket_versioning"
	refers_to(v, bucket, "bucket")
	some cfg in as_list(after_value(v, "versioning_configuration", []))
	cfg.status == "Enabled"
}

# legacy inline block on aws_s3_bucket
versioned(bucket) if {
	some cfg in as_list(after_value(bucket, "versioning", []))
	cfg.enabled == true
}

warn contains f if {
	some rc in changed
	rc.type == "aws_s3_bucket"
	not versioned(rc)
	f := pfinding(
		"GO-REL-003", "reliability", "MEDIUM", rc.address,
		sprintf("%s has no versioning: an overwritten or deleted object cannot be recovered.", [rc.address]),
	)
}

load_balanced_types := {"aws_lb", "aws_alb", "aws_elb", "aws_autoscaling_group"}

has_load_balancer if {
	some rc in after_state
	rc.type in load_balanced_types
}

new_instances := [rc | some rc in changed; rc.type == "aws_instance"]

warn contains f if {
	count(new_instances) == 1
	not has_load_balancer
	rc := new_instances[0]
	f := pfinding(
		"GO-REL-004", "reliability", "MEDIUM", rc.address,
		sprintf("%s is a single instance with no load balancer or auto scaling group: one failure takes the service down.", [rc.address]),
	)
}

pitr_enabled(rc) if {
	some p in as_list(after_value(rc, "point_in_time_recovery", []))
	p.enabled == true
}

warn contains f if {
	some rc in changed
	rc.type == "aws_dynamodb_table"
	not pitr_enabled(rc)
	f := pfinding(
		"GO-REL-005", "reliability", "MEDIUM", rc.address,
		sprintf("%s has no point-in-time recovery: accidental writes or deletes cannot be rolled back.", [rc.address]),
	)
}

monitored_types := {"aws_instance", "aws_db_instance", "aws_lambda_function", "aws_lb", "aws_dynamodb_table"}

has_alarm if {
	some rc in after_state
	rc.type == "aws_cloudwatch_metric_alarm"
}

# One finding per plan, reported on the first monitorable resource.
warn contains f if {
	not has_alarm
	monitored := {rc.address | some rc in changed; rc.type in monitored_types}
	count(monitored) > 0
	first := min(monitored)
	f := pfinding(
		"GO-REL-006", "reliability", "LOW", first,
		sprintf("No CloudWatch alarm watches %s or the other %d monitorable resource(s) in this plan: failures would go unnoticed.", [first, count(monitored) - 1]),
	)
}
