# GO-SG-001 (CRITICAL): SSH (22) or RDP (3389) open to 0.0.0.0/0 or ::/0.
#
# Covers all three ways Terraform expresses an ingress rule:
#   aws_security_group (inline ingress blocks), aws_security_group_rule
#   (type = "ingress") and aws_vpc_security_group_ingress_rule.
# Protocol "-1" (all traffic) exposes every port, so it counts too.
package ghostops

admin_ports := {22: "SSH", 3389: "RDP"}

world_cidrs := {"0.0.0.0/0", "::/0"}

ingress_entry(address, rule) := {
	"address": address,
	"protocol": lower(rule.protocol),
	"from_port": rule.from_port,
	"to_port": rule.to_port,
	"cidrs": array.concat(
		as_list(object.get(rule, "cidr_blocks", [])),
		as_list(object.get(rule, "ipv6_cidr_blocks", [])),
	),
}

sg_ingress contains ingress_entry(rc.address, rule) if {
	some rc in changed
	rc.type == "aws_security_group"
	some rule in as_list(object.get(rc.change.after, "ingress", []))
}

sg_ingress contains ingress_entry(rc.address, rule) if {
	some rc in changed
	rc.type == "aws_security_group_rule"
	rule := rc.change.after
	rule.type == "ingress"
}

sg_ingress contains entry if {
	some rc in changed
	rc.type == "aws_vpc_security_group_ingress_rule"
	rule := rc.change.after
	entry := {
		"address": rc.address,
		"protocol": lower(rule.ip_protocol),
		"from_port": object.get(rule, "from_port", null),
		"to_port": object.get(rule, "to_port", null),
		"cidrs": [c |
			some c in [object.get(rule, "cidr_ipv4", null), object.get(rule, "cidr_ipv6", null)]
			c != null
		],
	}
}

port_exposed(entry, _) if entry.protocol in {"-1", "all"}

port_exposed(entry, port) if {
	entry.protocol in {"tcp", "6"}
	entry.from_port <= port
	port <= entry.to_port
}

deny contains f if {
	some entry in sg_ingress
	some cidr in entry.cidrs
	cidr in world_cidrs
	some port, service in admin_ports
	port_exposed(entry, port)
	f := finding(
		"GO-SG-001",
		"CRITICAL",
		entry.address,
		sprintf("%s allows %s (port %d) from %s, i.e. from anywhere on the internet.", [entry.address, service, port, cidr]),
	)
}
