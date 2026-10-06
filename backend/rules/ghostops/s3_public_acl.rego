# GO-S3-001 (HIGH): S3 bucket ACL public-read or public-read-write.
#
# Covers aws_s3_bucket_acl and the legacy `acl` argument on aws_s3_bucket.
package ghostops

public_acls := {
	"public-read": "read every object in",
	"public-read-write": "read and overwrite every object in",
}

deny contains f if {
	some rc in changed
	rc.type in {"aws_s3_bucket_acl", "aws_s3_bucket"}
	acl := rc.change.after.acl
	some acl_name, effect in public_acls
	acl == acl_name
	f := finding(
		"GO-S3-001",
		"HIGH",
		rc.address,
		sprintf("%s sets the canned ACL %q: anyone on the internet can %s this bucket.", [rc.address, acl, effect]),
	)
}
