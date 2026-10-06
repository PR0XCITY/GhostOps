# GO-IAM-001 (CRITICAL): IAM policy allowing Action "*" on Resource "*".
#
# Checks managed policies and inline role/user/group policies. Action and
# Resource may be a string or a list; Statement may be an object or a list.
# A policy document only known after apply cannot be checked here.
package ghostops

iam_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

deny contains f if {
	some rc in changed
	rc.type in iam_policy_types
	doc := json.unmarshal(rc.change.after.policy)
	some statement in as_list(doc.Statement)
	statement.Effect == "Allow"
	"*" in as_list(object.get(statement, "Action", []))
	"*" in as_list(object.get(statement, "Resource", []))
	f := finding(
		"GO-IAM-001",
		"CRITICAL",
		rc.address,
		sprintf("%s allows every action (\"*\") on every resource (\"*\"): full administrator access to the AWS account.", [rc.address]),
	)
}
