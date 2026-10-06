# GO-RDS-001 (HIGH): RDS instance without storage encryption.
#
# Fails closed: anything other than storage_encrypted == true (false, unset, or
# unknown until apply) is reported, because encryption cannot be added later
# without rebuilding the database.
package ghostops

deny contains f if {
	some rc in changed
	rc.type == "aws_db_instance"
	not rc.change.after.storage_encrypted == true
	f := finding(
		"GO-RDS-001",
		"HIGH",
		rc.address,
		sprintf("%s does not enable storage encryption (storage_encrypted must be true), so data at rest is unencrypted.", [rc.address]),
	)
}
