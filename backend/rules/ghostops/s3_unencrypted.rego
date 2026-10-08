# GO-S3-002 (security, LOW, warn): S3 bucket without an explicit server-side
# encryption configuration.
#
# LOW and advisory because AWS has applied SSE-S3 to new objects by default since
# January 2023; the finding asks for the encryption to be stated in code.
package ghostops

encrypted_bucket(bucket) if {
	some e in after_state
	e.type == "aws_s3_bucket_server_side_encryption_configuration"
	refers_to(e, bucket, "bucket")
	some r in as_list(after_value(e, "rule", []))
	some d in as_list(object.get(r, "apply_server_side_encryption_by_default", []))
	is_string(d.sse_algorithm)
}

# legacy inline block on aws_s3_bucket
encrypted_bucket(bucket) if {
	some cfg in as_list(after_value(bucket, "server_side_encryption_configuration", []))
	count(as_list(object.get(cfg, "rule", []))) > 0
}

warn contains f if {
	some rc in changed
	rc.type == "aws_s3_bucket"
	not encrypted_bucket(rc)
	f := pfinding(
		"GO-S3-002", "security", "LOW", rc.address,
		sprintf("%s has no server-side encryption configuration in code: it relies on the AWS default (SSE-S3).", [rc.address]),
	)
}
