# Cost pillar (advisory: warn, never blocks).
#
# GO-COST-001 MEDIUM  EC2 instance larger than its stated usage needs: tag
#                     ExpectedCpuPercent <= 20 on a size above "small".
# GO-COST-002 LOW     gp2 storage where gp3 is about 20% cheaper (EBS volume,
#                     instance root volume, RDS storage_type).
# GO-COST-003 LOW     Cost-bearing resource with no tags at all (cannot be attributed).
package ghostops

right_sized := {"nano", "micro", "small"}

warn contains f if {
	some rc in changed
	rc.type == "aws_instance"
	tags := after_value(rc, "tags", null)
	is_object(tags)
	stated := object.get(tags, "ExpectedCpuPercent", "")
	regex.match(`^[0-9]+(\.[0-9]+)?$`, stated)
	to_number(stated) <= 20
	parts := split(after_value(rc, "instance_type", ""), ".")
	count(parts) == 2
	not parts[1] in right_sized
	f := pfinding(
		"GO-COST-001", "cost", "MEDIUM", rc.address,
		sprintf("%s is a %s but its stated usage is %s%% CPU: a smaller size (for example t3.small) would cost less.", [rc.address, after_value(rc, "instance_type", ""), stated]),
	)
}

gp2_volume(rc) if {
	rc.type == "aws_ebs_volume"
	after_value(rc, "type", null) == "gp2"
}

gp2_volume(rc) if {
	rc.type == "aws_db_instance"
	after_value(rc, "storage_type", null) == "gp2"
}

gp2_volume(rc) if {
	rc.type == "aws_instance"
	some root in as_list(after_value(rc, "root_block_device", []))
	root.volume_type == "gp2"
}

warn contains f if {
	some rc in changed
	gp2_volume(rc)
	f := pfinding(
		"GO-COST-002", "cost", "LOW", rc.address,
		sprintf("%s uses gp2 storage: gp3 costs about 20%% less with the same or better baseline performance.", [rc.address]),
	)
}

cost_taggable := {
	"aws_instance", "aws_ebs_volume", "aws_s3_bucket", "aws_db_instance", "aws_dynamodb_table",
	"aws_lambda_function", "aws_lb", "aws_nat_gateway", "aws_eip", "aws_elasticache_cluster",
}

warn contains f if {
	some rc in changed
	rc.type in cost_taggable
	map_size(rc, "tags") == 0
	map_size(rc, "tags_all") == 0
	f := pfinding(
		"GO-COST-003", "cost", "LOW", rc.address,
		sprintf("%s has no tags, so its cost cannot be attributed to an owner, team or environment.", [rc.address]),
	)
}
