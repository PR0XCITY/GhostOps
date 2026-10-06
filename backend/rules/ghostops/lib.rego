# Shared helpers for GhostOps policies.
#
# Input: the plan JSON from `terraform show -json <planfile>`.
# Output (data.ghostops.result): {"deny": [finding...], "warn": [finding...]}
# where finding = {"rule_id", "severity", "address", "message"}.
package ghostops

result := {"deny": deny, "warn": warn}

finding(rule_id, severity, address, message) := {
	"rule_id": rule_id,
	"severity": severity,
	"address": address,
	"message": message,
}

managed(rc) if object.get(rc, "mode", "managed") == "managed"

# Resources this plan creates or modifies (including replacements). Unchanged
# (no-op) resources are not judged: they are not part of the proposed change.
changed contains rc if {
	some rc in input.resource_changes
	managed(rc)
	some action in rc.change.actions
	action in {"create", "update"}
}

# Resources this plan destroys, either outright or as part of a replacement.
deleted contains rc if {
	some rc in input.resource_changes
	managed(rc)
	"delete" in rc.change.actions
}

# Normalize "x", ["x"], null into a list.
as_list(x) := x if is_array(x)

as_list(x) := [] if x == null

as_list(x) := [x] if {
	not is_array(x)
	x != null
}
