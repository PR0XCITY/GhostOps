"""Blast radius: before/after resource graphs from a Terraform plan, and their diff.

Nodes are managed resources. The before graph holds every resource with a
`before` state, the after graph every resource with an `after` state. An edge
A -> B means "A references B" (e.g. an instance -> its security group, a bucket
ACL -> its bucket). Edges come from two sources:

  1. configuration references (`configuration.*.expressions[*].references` and
     `depends_on`), which describe the after state. These are the only way to
     link resources being created, whose IDs are unknown until apply.
  2. value matching: an attribute value equal to another resource's `id` or
     `arn`. This links resources that already exist, in both graphs.

Each edge records which attribute(s) produced it (`via`).

analyze(plan) returns:
  newly_public   resources exposed to 0.0.0.0/0 or ::/0 after, but not before
  iam_widened    IAM policies/attachments that grant more than before
  created        resources the plan creates (including replacements)
  destroyed      resources the plan destroys (including replacements)
  edges_added / edges_removed   reference changes between the two graphs
  graph          the after graph as JSON {nodes, edges}, with a risk flag per node

Exposure rules ("public"):
  - a security group with an ingress rule from 0.0.0.0/0 or ::/0 (inline,
    aws_security_group_rule or aws_vpc_security_group_ingress_rule), any port;
  - any non-security-group resource attached to such a group (RDS only when
    publicly_accessible = true);
  - an S3 bucket with a public-read(-write) ACL, unless the bucket ignores ACLs
    (public access block ignore_public_acls, or ownership BucketOwnerEnforced);
  - an S3 bucket whose bucket policy allows Principal "*", unless the public
    access block sets restrict_public_buckets.
Values unknown until apply are treated as not public, except IAM policy
documents, which are reported as widened with unknown = true (fail closed).

CLI: python -m app.blast_radius <plan.json>   (prints the report as JSON)
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterator

import networkx as nx

from app.plan_parser import PlanParseError, ResourceChange, parse_plan

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
SG_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule",
}
PUBLIC_ACLS = {"public-read", "public-read-write"}
POLICY_DOC_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
POLICY_ATTACHMENT_TYPES = {
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
}
ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"
# First segment of a Terraform reference that is not a managed resource.
_NOT_RESOURCES = {"var", "local", "data", "module", "each", "count", "path", "self", "terraform"}
_INDEX = re.compile(r"\[[^\]]*\]")


# --- graph construction --------------------------------------------------------


def _walk_references(expr: Any) -> Iterator[str]:
    if isinstance(expr, dict):
        refs = expr.get("references")
        if isinstance(refs, list):
            yield from (r for r in refs if isinstance(r, str))
        for key, value in expr.items():
            if key not in ("references", "constant_value"):
                yield from _walk_references(value)
    elif isinstance(expr, list):
        for item in expr:
            yield from _walk_references(item)


def _ref_to_address(ref: str, prefix: str) -> str | None:
    parts = ref.split(".")
    if len(parts) < 2 or parts[0] in _NOT_RESOURCES:
        return None
    return f"{prefix}{parts[0]}.{parts[1].split('[')[0]}"


def config_edges(plan: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(source, target, attribute) for every resource reference in the configuration.

    Addresses are instance-less (no [0] / ["key"]); callers map them to instances.
    """
    edges: list[tuple[str, str, str]] = []

    def visit(module: dict[str, Any], prefix: str) -> None:
        for res in module.get("resources", []) or []:
            if res.get("mode", "managed") != "managed" or "address" not in res:
                continue
            src = prefix + res["address"]
            for attr, expr in (res.get("expressions") or {}).items():
                for ref in _walk_references(expr):
                    dst = _ref_to_address(ref, prefix)
                    if dst and dst != src:
                        edges.append((src, dst, attr))
            for dep in res.get("depends_on") or []:
                dst = _ref_to_address(dep, prefix)
                if dst and dst != src:
                    edges.append((src, dst, "depends_on"))
        for name, call in (module.get("module_calls") or {}).items():
            visit(call.get("module") or {}, f"{prefix}module.{name}.")

    visit((plan.get("configuration") or {}).get("root_module") or {}, "")
    return edges


def _string_leaves(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _string_leaves(v)
    elif isinstance(value, list):
        for v in value:
            yield from _string_leaves(v)


def _add_edge(graph: nx.DiGraph, src: str, dst: str, via: str) -> None:
    if graph.has_edge(src, dst):
        graph.edges[src, dst]["via"].add(via)
    else:
        graph.add_edge(src, dst, via={via})


def build_graph(changes: list[ResourceChange], side: str, refs: list[tuple[str, str, str]] = ()) -> nx.DiGraph:
    """Graph of the `before` or `after` side of the plan."""
    if side not in ("before", "after"):
        raise ValueError(f"side must be 'before' or 'after', got {side!r}")
    graph = nx.DiGraph()
    for c in changes:
        values = c.before if side == "before" else c.after
        if values is None:
            continue
        graph.add_node(
            c.address,
            type=c.type,
            action=c.action,
            values=values,
            unknown=c.after_unknown if side == "after" else {},
        )

    # 1. configuration references, mapped onto every instance of each resource
    instances: dict[str, list[str]] = defaultdict(list)
    for node in graph.nodes:
        instances[_INDEX.sub("", node)].append(node)
    for src, dst, via in refs:
        for s in instances.get(src, []):
            for d in instances.get(dst, []):
                if s != d:
                    _add_edge(graph, s, d, via)

    # 2. attribute values equal to another resource's id or arn
    identity: dict[str, set[str]] = defaultdict(set)
    for node, data in graph.nodes(data=True):
        for key in ("id", "arn"):
            value = data["values"].get(key)
            if isinstance(value, str) and value:
                identity[value].add(node)
    owners = {value: _primary_owners(graph, nodes) for value, nodes in identity.items()}
    for node, data in graph.nodes(data=True):
        for attr, value in data["values"].items():
            if attr in ("id", "arn"):
                continue
            for leaf in _string_leaves(value):
                for target in owners.get(leaf, ()):
                    if target != node:
                        _add_edge(graph, node, target, attr)
    return graph


def _primary_owners(graph: nx.DiGraph, nodes: set[str]) -> set[str]:
    """Which of several resources sharing one id a reference to that id means.

    AWS sub-resources often reuse the parent's id: aws_s3_bucket_policy,
    aws_s3_bucket_public_access_block, ... all have id = bucket name. Terraform
    names them <parent type>_<suffix>, so prefer the type that prefixes the others.
    """
    if len(nodes) == 1:
        return nodes
    types = {n: graph.nodes[n]["type"] for n in nodes}
    primary = {n for n, t in types.items() if all(other.startswith(t) for other in types.values())}
    return primary or nodes


# --- exposure -------------------------------------------------------------------


def _world_ingress(node_type: str, values: dict[str, Any]) -> bool:
    if node_type == "aws_security_group":
        for rule in values.get("ingress") or []:
            cidrs = (rule.get("cidr_blocks") or []) + (rule.get("ipv6_cidr_blocks") or [])
            if WORLD_CIDRS & set(cidrs):
                return True
        return False
    if node_type == "aws_security_group_rule":
        cidrs = (values.get("cidr_blocks") or []) + (values.get("ipv6_cidr_blocks") or [])
        return values.get("type") == "ingress" and bool(WORLD_CIDRS & set(cidrs))
    if node_type == "aws_vpc_security_group_ingress_rule":
        return bool(WORLD_CIDRS & {values.get("cidr_ipv4"), values.get("cidr_ipv6")})
    return False


def _neighbors_of_type(graph: nx.DiGraph, node: str, node_type: str, *, incoming: bool = False) -> list[str]:
    nodes = graph.predecessors(node) if incoming else graph.successors(node)
    return [n for n in nodes if graph.nodes[n]["type"] == node_type]


def _bucket_ignores_acls(graph: nx.DiGraph, bucket: str) -> bool:
    for pab in _neighbors_of_type(graph, bucket, "aws_s3_bucket_public_access_block", incoming=True):
        if graph.nodes[pab]["values"].get("ignore_public_acls") is True:
            return True
    for oc in _neighbors_of_type(graph, bucket, "aws_s3_bucket_ownership_controls", incoming=True):
        for rule in graph.nodes[oc]["values"].get("rule") or []:
            if rule.get("object_ownership") == "BucketOwnerEnforced":
                return True
    return False


def _bucket_restricts_policy(graph: nx.DiGraph, bucket: str) -> bool:
    return any(
        graph.nodes[pab]["values"].get("restrict_public_buckets") is True
        for pab in _neighbors_of_type(graph, bucket, "aws_s3_bucket_public_access_block", incoming=True)
    )


def _as_list(x: Any) -> list[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _policy_allows_everyone(document: Any) -> bool:
    try:
        doc = json.loads(document)
    except (TypeError, ValueError):
        return False
    for st in _as_list(doc.get("Statement")) if isinstance(doc, dict) else []:
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        if principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))):
            return True
    return False


def exposure(graph: nx.DiGraph) -> tuple[dict[str, set[str]], set[str]]:
    """(public resource -> resources that make it public, resources that open access)."""
    public: dict[str, set[str]] = defaultdict(set)
    openers: set[str] = set()

    world_sgs: dict[str, set[str]] = defaultdict(set)
    for node, data in graph.nodes(data=True):
        if not _world_ingress(data["type"], data["values"]):
            continue
        openers.add(node)
        if data["type"] == "aws_security_group":
            world_sgs[node].add(node)
        else:  # rule resource: the group it belongs to, not a source group it allows
            for sg in _neighbors_of_type(graph, node, "aws_security_group"):
                if "security_group_id" in graph.edges[node, sg]["via"]:
                    world_sgs[sg].add(node)
    for sg, via in world_sgs.items():
        public[sg] |= via

    for node, data in graph.nodes(data=True):
        if data["type"] in SG_TYPES:
            continue  # an SG allowing traffic from a public SG is not itself public
        if data["type"] == "aws_db_instance" and data["values"].get("publicly_accessible") is not True:
            continue
        for sg in graph.successors(node):
            if sg in world_sgs:
                public[node].add(sg)

    for node, data in graph.nodes(data=True):
        values = data["values"]
        if data["type"] == "aws_s3_bucket_acl" and values.get("acl") in PUBLIC_ACLS:
            for bucket in _neighbors_of_type(graph, node, "aws_s3_bucket"):
                if not _bucket_ignores_acls(graph, bucket):
                    public[bucket].add(node)
                    openers.add(node)
        elif data["type"] == "aws_s3_bucket" and values.get("acl") in PUBLIC_ACLS:
            if not _bucket_ignores_acls(graph, node):
                public[node].add(node)
                openers.add(node)
        elif data["type"] == "aws_s3_bucket_policy" and _policy_allows_everyone(values.get("policy")):
            for bucket in _neighbors_of_type(graph, node, "aws_s3_bucket"):
                if not _bucket_restricts_policy(graph, bucket):
                    public[bucket].add(node)
                    openers.add(node)
    return dict(public), openers


# --- IAM widening ---------------------------------------------------------------


def _statements(document: Any) -> list[dict[str, Any]] | None:
    try:
        doc = json.loads(document)
    except (TypeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    return [s for s in _as_list(doc.get("Statement")) if isinstance(s, dict)]


def _grants(statements: list[dict[str, Any]], effect: str) -> set[tuple[str, str]]:
    """(action, resource) pairs. NotAction / NotResource count as "*" (conservative)."""
    pairs: set[tuple[str, str]] = set()
    for st in statements:
        if st.get("Effect") != effect:
            continue
        actions = ["*"] if "NotAction" in st else _as_list(st.get("Action"))
        resources = ["*"] if "NotResource" in st else _as_list(st.get("Resource"))
        pairs |= {(str(a).lower(), str(r)) for a in actions for r in resources}
    return pairs


def _covered(grant: tuple[str, str], by: set[tuple[str, str]]) -> bool:
    return any(fnmatchcase(grant[0], a) and fnmatchcase(grant[1], r) for a, r in by)


def iam_widened(changes: list[ResourceChange]) -> list[dict[str, Any]]:
    widened = []
    for c in changes:
        if c.after is None:
            continue
        entry = {"address": c.address, "type": c.type, "added_grants": [], "removed_denies": [],
                 "admin": False, "unknown": False}
        if c.type in POLICY_DOC_TYPES:
            if c.after_unknown.get("policy") is True:
                entry["unknown"] = True  # document only known after apply: cannot prove it is safe
                widened.append(entry)
                continue
            after = _statements(c.after.get("policy"))
            before = _statements(c.before.get("policy")) if c.before else []
            if after is None:
                entry["unknown"] = True
                widened.append(entry)
                continue
            before = before or []
            allow_before, allow_after = _grants(before, "Allow"), _grants(after, "Allow")
            deny_before, deny_after = _grants(before, "Deny"), _grants(after, "Deny")
            added = sorted(g for g in allow_after if not _covered(g, allow_before))
            removed = sorted(g for g in deny_before if not _covered(g, deny_after))
            if not added and not removed:
                continue
            entry["added_grants"] = [{"action": a, "resource": r} for a, r in added]
            entry["removed_denies"] = [{"action": a, "resource": r} for a, r in removed]
            entry["admin"] = ("*", "*") in added
            widened.append(entry)
        elif c.type in POLICY_ATTACHMENT_TYPES:
            arn = c.after.get("policy_arn")
            before_arn = (c.before or {}).get("policy_arn")
            if isinstance(arn, str) and arn.endswith(ADMIN_POLICY_SUFFIX) and arn != before_arn:
                entry["added_grants"] = [{"action": "*", "resource": "*"}]
                entry["admin"] = True
                widened.append(entry)
    return sorted(widened, key=lambda e: e["address"])


# --- analysis -------------------------------------------------------------------


def export_graph(graph: nx.DiGraph, risks: dict[str, set[str]]) -> dict[str, list[dict[str, Any]]]:
    nodes = [
        {
            "id": node,
            "type": data["type"],
            "action": data["action"],
            "risk": bool(risks.get(node)),
            "risk_reasons": sorted(risks.get(node, ())),
        }
        for node, data in sorted(graph.nodes(data=True))
    ]
    edges = [
        {"source": u, "target": v, "via": sorted(data["via"])}
        for u, v, data in sorted(graph.edges(data=True), key=lambda e: (e[0], e[1]))
    ]
    return {"nodes": nodes, "edges": edges}


def analyze(plan: dict[str, Any]) -> dict[str, Any]:
    changes = parse_plan(plan)
    refs = config_edges(plan)
    before = build_graph(changes, "before")
    after = build_graph(changes, "after", refs)

    public_before, _ = exposure(before)
    public_after, openers_after = exposure(after)
    widened = iam_widened(changes)

    newly_public = [
        {"address": node, "type": after.nodes[node]["type"], "via": sorted(via)}
        for node, via in sorted(public_after.items())
        if node not in public_before
    ]

    risks: dict[str, set[str]] = defaultdict(set)
    for node in public_after:
        risks[node].add("public_exposure")
    for node in openers_after:
        risks[node].add("opens_public_access")
    for entry in widened:
        risks[entry["address"]].add("iam_widened")
        if entry["admin"]:
            risks[entry["address"]].add("iam_admin")

    def edge_list(edges: set[tuple[str, str]]) -> list[dict[str, str]]:
        return [{"source": u, "target": v} for u, v in sorted(edges)]

    return {
        "newly_public": newly_public,
        "iam_widened": widened,
        "created": [{"address": c.address, "type": c.type} for c in changes if c.action in ("create", "replace")],
        "destroyed": [{"address": c.address, "type": c.type} for c in changes if c.action in ("delete", "replace")],
        "edges_added": edge_list(set(after.edges) - set(before.edges)),
        "edges_removed": edge_list(set(before.edges) - set(after.edges)),
        "graph": export_graph(after, risks),
    }


def analyze_file(path: str | Path) -> dict[str, Any]:
    try:
        plan = json.loads(Path(path).read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanParseError(f"invalid JSON: {exc}") from None
    return analyze(plan)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m app.blast_radius <plan.json>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(analyze_file(sys.argv[1]), indent=2))
