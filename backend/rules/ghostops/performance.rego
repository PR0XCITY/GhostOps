# Performance pillar (advisory: warn, never blocks).
#
# GO-PERF-001 LOW     Lambda at the 128 MB minimum (CPU scales with memory; unset = 128).
# GO-PERF-002 MEDIUM  Lambda timeout at the 900 s maximum: effectively no limit, so a
#                     hung invocation holds concurrency (and bills) for 15 minutes.
# GO-PERF-003 MEDIUM  DynamoDB PROVISIONED capacity with no auto scaling target:
#                     traffic above the fixed capacity is throttled.
package ghostops

warn contains f if {
	some rc in changed
	rc.type == "aws_lambda_function"
	memory := after_value(rc, "memory_size", 128)
	is_number(memory)
	memory <= 128
	f := pfinding(
		"GO-PERF-001", "performance", "LOW", rc.address,
		sprintf("%s has %d MB of memory, the minimum: Lambda CPU scales with memory, so it runs and cold-starts slowly.", [rc.address, memory]),
	)
}

warn contains f if {
	some rc in changed
	rc.type == "aws_lambda_function"
	timeout := after_value(rc, "timeout", 3)
	is_number(timeout)
	timeout >= 900
	f := pfinding(
		"GO-PERF-002", "performance", "MEDIUM", rc.address,
		sprintf("%s has a %d s timeout, the maximum: a hung invocation holds concurrency and is billed for 15 minutes.", [rc.address, timeout]),
	)
}

autoscaled(table) if {
	some t in after_state
	t.type == "aws_appautoscaling_target"
	after_value(t, "service_namespace", "") == "dynamodb"
	after_value(t, "resource_id", "") == concat("", ["table/", after_value(table, "name", "")])
}

autoscaled(table) if {
	some t in after_state
	t.type == "aws_appautoscaling_target"
	not module_resource(table)
	config_address(table) in references(t, "resource_id")
}

warn contains f if {
	some rc in changed
	rc.type == "aws_dynamodb_table"
	after_value(rc, "billing_mode", "PROVISIONED") == "PROVISIONED"
	not autoscaled(rc)
	f := pfinding(
		"GO-PERF-003", "performance", "MEDIUM", rc.address,
		sprintf("%s uses PROVISIONED capacity with no auto scaling: requests above the fixed capacity are throttled.", [rc.address]),
	)
}
