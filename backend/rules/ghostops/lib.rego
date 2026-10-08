# Shared helpers for GhostOps policies.
#
# Input: the plan JSON from `terraform show -json <planfile>`.
# Output (data.ghostops.result): {"deny": [finding...], "warn": [finding...]}
# where finding = {"rule_id", "pillar", "severity", "address", "message"}.
#
# pillar is one of security | reliability | cost | performance. Only security
# findings go in `deny`; the other pillars are advisory and go in `warn`.
package ghostops

result := {"deny": deny, "warn": warn}

pfinding(rule_id, pillar, severity, address, message) := {
	"rule_id": rule_id,
	"pillar": pillar,
	"severity": severity,
	"address": address,
	"message": message,
}

# The original security rules.
finding(rule_id, severity, address, message) := pfinding(rule_id, "security", severity, address, message)

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

# Resources that exist after this plan: created, updated or unchanged (not deleted).
# Used to look for companions (a versioning config, an alarm, a load balancer) that
# may already exist and so appear as no-op.
after_state contains rc if {
	some rc in input.resource_changes
	managed(rc)
	rc.change.actions != ["delete"]
	is_object(rc.change.after)
}

module_resource(rc) if object.get(rc, "module_address", "") != ""

# Root-module configuration address: aws_x.y[0] -> aws_x.y
config_address(rc) := concat(".", [rc.type, rc.name])

# References written in the configuration for one argument of a root-module
# resource, e.g. {"aws_s3_bucket.logs.id", "aws_s3_bucket.logs"}.
references(rc, attr) := {ref |
	not module_resource(rc)
	some r in object.get(input, ["configuration", "root_module", "resources"], [])
	r.address == config_address(rc)
	some ref in object.get(r, ["expressions", attr, "references"], [])
}

# child (e.g. aws_s3_bucket_versioning) points at parent through argument attr:
# by a configuration reference, or by an equal known value.
refers_to(child, parent, attr) if {
	not module_resource(parent)
	config_address(parent) in references(child, attr)
}

refers_to(child, parent, attr) if {
	value := object.get(child.change.after, attr, null)
	is_string(value)
	value == object.get(parent.change.after, attr, null)
}

after_value(rc, key, fallback) := object.get(rc.change.after, key, fallback)

# Number of entries in a map attribute such as tags (0 for null or unknown).
map_size(rc, key) := count(m) if {
	m := object.get(rc.change.after, key, null)
	is_object(m)
}

map_size(rc, key) := 0 if {
	not is_object(object.get(rc.change.after, key, null))
}
