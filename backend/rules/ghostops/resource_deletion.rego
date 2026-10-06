# GO-DEL-001 (MEDIUM, warn): any resource deletion, including replacements
# (Terraform destroys the old object before or after creating the new one).
package ghostops

deletion_verb(actions) := "replaced (destroyed and re-created)" if "create" in actions

deletion_verb(actions) := "destroyed" if not "create" in actions

warn contains f if {
	some rc in deleted
	f := finding(
		"GO-DEL-001",
		"MEDIUM",
		rc.address,
		sprintf("%s will be %s. Anything it holds or serves may be lost.", [rc.address, deletion_verb(rc.change.actions)]),
	)
}
