"""A remediation suggestion for every risk flag.

The fix itself (which setting to change, to what) is decided here by fixed rules,
never by the LLM:

  - for architectures built from the catalog: a change to a catalog field of the
    service that owns the flagged resource, e.g. {service: web, field:
    ssh_source_cidr, to: 10.0.0.0/16}. Applying the change and re-analysing clears
    the flag (tests/test_architecture.py checks this).
  - for plain Terraform plans: the Terraform attribute to change.

Groq only rewrites the explanatory sentence. It receives, per flag: the rule id
and title, the severity, the resource TYPE, and the field name plus GhostOps' own
safe target value (a constant from this module, never the user's current value).
Any Groq failure, or an answer that is not a list of sentences of the right
length, falls back to the template sentence, and generated_by says which.

Remediation = {"summary": str, "config_change": [change, ...], "generated_by": "groq" | "template"}
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

from app.catalog import CATALOG

PRIVATE_CIDR = "10.0.0.0/16"
LEAST_PRIVILEGE_ACTIONS = ["s3:GetObject"]
BACKUP_DAYS = 7
RIGHT_SIZE = "t3.small"
LAMBDA_MEMORY_MB = 256
LAMBDA_TIMEOUT_S = 30
SCOPED_RESOURCE = "arn:aws:s3:::example-bucket/*"


def _change(service, field: str, to: Any) -> dict[str, Any]:
    return {"service": service.slug, "type": service.type, "field": field, "from": service.config[field], "to": to}


def _tf_change(resource: str, attribute: str, to: Any) -> dict[str, Any]:
    return {"resource": resource, "attribute": attribute, "to": to}


def _service_fix(rule: str, service) -> tuple[list[dict[str, Any]], str]:
    """(config changes, template sentence) for a flag on a catalog service."""
    t, c, name = service.type, service.config, service.slug
    if rule in ("GO-SG-001", "GO-EXPOSE-001"):
        if t == "ec2":
            return [_change(service, "ssh_source_cidr", PRIVATE_CIDR)], (
                f"Restrict SSH on {name} to a private range: set ssh_source_cidr to {PRIVATE_CIDR}.")
        if t == "vpc":
            return [_change(service, "ingress_cidr", PRIVATE_CIDR)], (
                f"Limit the {name} security group to a private range: set ingress_cidr to {PRIVATE_CIDR}.")
        if t == "alb":
            changes = [_change(service, "ingress_cidr", PRIVATE_CIDR)]
            if not c["internal"]:
                changes.insert(0, _change(service, "internal", True))
            return changes, (f"Keep the {name} load balancer private: make it internal and set ingress_cidr "
                             f"to {PRIVATE_CIDR} (put a CDN or WAF in front if it must be public).")
        if t == "s3":
            return [_change(service, "public_access", False)], (
                f"Turn off public access on bucket {name}: set public_access to false (share objects with "
                "presigned URLs or CloudFront instead).")
        if t == "rds":
            return [_change(service, "publicly_accessible", False)], (
                f"Make database {name} private: set publicly_accessible to false.")
    if rule == "GO-S3-001" and t == "s3":
        return [_change(service, "public_access", False)], (
            f"Remove the public-read ACL from bucket {name}: set public_access to false.")
    if rule in ("GO-IAM-001", "GO-IAMW-001") and t == "iam":
        changes = []
        if "*" in c["actions"]:
            changes.append(_change(service, "actions", LEAST_PRIVILEGE_ACTIONS))
        if c["resource"] == "*":
            changes.append(_change(service, "resource", SCOPED_RESOURCE))
        if not changes:  # widened but already scoped (e.g. new permissions): nothing to force
            return [], f"Review the permissions granted by {name}; keep only the actions the workload needs."
        return changes, (f"Apply least privilege to {name}: grant only the actions the workload needs (for example "
                         f"{', '.join(LEAST_PRIVILEGE_ACTIONS)}) on a specific resource ARN, never * on *.")
    if rule == "GO-RDS-001" and t == "rds":
        return [_change(service, "encrypted", True)], (
            f"Encrypt database {name} at rest: set encrypted to true (it cannot be added later without a rebuild).")
    # advisory pillars
    if rule == "GO-REL-001" and t == "rds":
        return [_change(service, "multi_az", True)], (
            f"Run database {name} in two availability zones: set multi_az to true (roughly doubles its instance cost).")
    if rule == "GO-REL-002" and t == "rds":
        return [_change(service, "backup_retention_days", BACKUP_DAYS)], (
            f"Turn on automated backups for {name}: set backup_retention_days to {BACKUP_DAYS}.")
    if rule == "GO-REL-003" and t == "s3":
        return [_change(service, "versioning", True)], (
            f"Keep old object versions in bucket {name}: set versioning to true.")
    if rule == "GO-S3-002" and t == "s3":
        return [_change(service, "encryption", True)], (
            f"State the encryption of bucket {name} in code: set encryption to true (AES-256).")
    if rule == "GO-REL-004" and t == "ec2":
        return [_change(service, "count", 2)], (
            f"Run at least two {name} instances (set count to 2) and add an Application Load Balancer in front of them.")
    if rule == "GO-REL-005" and t == "dynamodb":
        return [_change(service, "point_in_time_recovery", True)], (
            f"Turn on point-in-time recovery for table {name}: set point_in_time_recovery to true.")
    if rule == "GO-REL-006":
        return [], (f"Add a CloudWatch alarm service (for example CPUUtilization or Errors) that watches {name}, "
                    "so failures are noticed.")
    if rule == "GO-COST-001" and t == "ec2":
        return [_change(service, "instance_type", RIGHT_SIZE)], (
            f"Right-size {name}: at {c['expected_cpu_percent']}% expected CPU, set instance_type to {RIGHT_SIZE}.")
    if rule == "GO-PERF-001" and t == "lambda":
        return [_change(service, "memory_mb", LAMBDA_MEMORY_MB)], (
            f"Give function {name} more CPU: set memory_mb to {LAMBDA_MEMORY_MB} (CPU scales with memory).")
    if rule == "GO-PERF-002" and t == "lambda":
        return [_change(service, "timeout_s", LAMBDA_TIMEOUT_S)], (
            f"Bound function {name}: set timeout_s to {LAMBDA_TIMEOUT_S} (raise it only if real runs need longer).")
    if rule == "GO-PERF-003" and t == "dynamodb":
        return [_change(service, "billing_mode", "PAY_PER_REQUEST")], (
            f"Let table {name} scale with traffic: set billing_mode to PAY_PER_REQUEST (or add auto scaling).")
    return [], ""


def _terraform_fix(rule: str, resource: str, rtype: str) -> tuple[list[dict[str, Any]], str]:
    """(attribute changes, template sentence) for a flag on plain Terraform."""
    if rule == "GO-SG-001" or (rule == "GO-EXPOSE-001" and rtype in ("aws_security_group", "aws_security_group_rule")):
        return [_tf_change(resource, "ingress.cidr_blocks", [PRIVATE_CIDR])], (
            f"In {resource}, replace 0.0.0.0/0 (and ::/0) in the ingress rule with a private range such as "
            f"{PRIVATE_CIDR}, or reach the host through SSM Session Manager.")
    if rule == "GO-EXPOSE-001":
        return [], (f"{resource} is reachable from the internet through the resource named in the flag; "
                    "restrict that security group, ACL or policy instead of this resource.")
    if rule in ("GO-IAM-001", "GO-IAMW-001"):
        return [_tf_change(resource, "policy.Statement.Action", LEAST_PRIVILEGE_ACTIONS),
                _tf_change(resource, "policy.Statement.Resource", SCOPED_RESOURCE)], (
            f"In {resource}, replace Action \"*\" / Resource \"*\" with the specific actions and resource ARNs "
            "the workload needs.")
    if rule == "GO-S3-001":
        return [_tf_change(resource, "acl", "private")], (
            f"In {resource}, set acl = \"private\" and keep the bucket's public access block enabled.")
    if rule == "GO-RDS-001":
        return [_tf_change(resource, "storage_encrypted", True)], (
            f"In {resource}, set storage_encrypted = true.")
    if rule == "GO-DEL-001":
        return [_tf_change(resource, "lifecycle.prevent_destroy", True)], (
            f"Confirm that destroying {resource} is intended; if it holds data, back it up first or add "
            "lifecycle { prevent_destroy = true }.")
    simple = {
        "GO-REL-001": ("multi_az", True, "run it in two availability zones"),
        "GO-REL-002": ("backup_retention_period", BACKUP_DAYS, "keep automated backups"),
        "GO-REL-005": ("point_in_time_recovery.enabled", True, "turn on point-in-time recovery"),
        "GO-COST-001": ("instance_type", RIGHT_SIZE, "match the size to the stated usage"),
        "GO-PERF-001": ("memory_size", LAMBDA_MEMORY_MB, "give it more memory and CPU"),
        "GO-PERF-002": ("timeout", LAMBDA_TIMEOUT_S, "bound its run time"),
        "GO-PERF-003": ("billing_mode", "PAY_PER_REQUEST", "scale with traffic (or add aws_appautoscaling_target)"),
    }
    if rule in simple:
        attribute, to, why = simple[rule]
        return [_tf_change(resource, attribute, to)], f"In {resource}, set {attribute} = {json.dumps(to)} to {why}."
    if rule == "GO-REL-003":
        return [_tf_change(resource, "aws_s3_bucket_versioning.status", "Enabled")], (
            f"Add an aws_s3_bucket_versioning resource for {resource} with status = \"Enabled\".")
    if rule == "GO-S3-002":
        return [_tf_change(resource, "aws_s3_bucket_server_side_encryption_configuration.sse_algorithm", "AES256")], (
            f"Add an aws_s3_bucket_server_side_encryption_configuration for {resource} (AES256 or aws:kms).")
    if rule == "GO-REL-004":
        return [], f"Run {resource} as two or more instances behind a load balancer or in an auto scaling group."
    if rule == "GO-REL-006":
        return [], f"Add an aws_cloudwatch_metric_alarm that watches {resource} (and the other new resources)."
    if rule == "GO-COST-002":
        return [_tf_change(resource, "type", "gp3")], f"In {resource}, use gp3 instead of gp2 (about 20% cheaper)."
    if rule == "GO-COST-003":
        return [_tf_change(resource, "tags.Owner", "your-team")], (
            f"Tag {resource} (at least Name and Owner), or set default_tags on the AWS provider.")
    return [], ""


GENERIC = {
    "GO-SHADOW-001": "Fix the error reported by the shadow run (see shadow_run.error) and analyse again; if it is "
                     "a MiniStack limitation, a reviewer can approve after checking the plan by hand.",
    "GO-ENGINE-001": "Install or repair the OPA policy engine (opa on PATH or GHOSTOPS_OPA_BIN) and analyse again.",
    "GO-DEL-001": "Confirm the deletion is intended and that any data is backed up.",
}


def template_remediation(flag: dict[str, str], generated=None) -> tuple[list[dict[str, Any]], str]:
    resource = flag["resource"]
    rtype = resource.split(".")[0] if "." in resource else "resource"
    owner = generated.owner(resource) if generated is not None else None
    if owner is not None:
        changes, text = _service_fix(flag["rule"], owner)
        if text:
            return changes, text
    if not resource.startswith("("):
        changes, text = _terraform_fix(flag["rule"], resource, rtype)
        if text:
            return changes, text
    return [], GENERIC.get(flag["rule"], "Review this finding and adjust the configuration it names.")


def groq_facts(flags: list[dict[str, str]], fixes: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """What the LLM may see: structure and GhostOps' own target values, never user values."""
    from app.certificate import RULE_TITLES, SEVERITY_ORDER, resource_type, sanitize_text

    facts = []
    for flag, changes in zip(flags, fixes):
        facts.append({
            "rule": sanitize_text(flag["rule"]),
            "title": RULE_TITLES.get(flag["rule"], "Policy finding"),
            "severity": flag["severity"] if flag["severity"] in SEVERITY_ORDER else "UNKNOWN",
            "resource_type": resource_type(flag["resource"]),
            "fix": [{"field": c.get("field") or c.get("attribute"), "set_to": _describe(c["to"])} for c in changes],
        })
    return facts


def _describe(value: Any) -> Any:
    """ARNs are described, not sent: the sanitizer would redact them from the answer anyway,
    and the exact value is in config_change."""
    if isinstance(value, str) and value.startswith("arn:"):
        return "a specific resource ARN"
    return value


def groq_sentences(facts: list[dict[str, Any]]) -> list[str] | None:
    """One sentence per finding from Groq, or None on any failure."""
    from app import certificate

    key = certificate.setting("GROQ_API_KEY")
    if not key or not facts:
        return None
    body = {
        "model": certificate.setting("GROQ_MODEL", "openai/gpt-oss-120b"),
        "temperature": 0.2,
        "max_tokens": 1500,
        "messages": [
            {"role": "system", "content": (
                "You write remediation advice for cloud infrastructure findings. For each finding, write one "
                "imperative sentence (max 40 words) telling the engineer how to fix it, naming the exact field "
                "and value given in 'fix' when present. Use only the facts given; do not invent resource names. "
                'Reply with JSON only: {"remediations": ["...", ...]} in the same order as the input.')},
            {"role": "user", "content": json.dumps({"findings": facts}, sort_keys=True)},
        ],
    }
    try:
        reply = certificate._post_json(certificate.GROQ_URL, body, {"Authorization": f"Bearer {key}"}, 45)
        text = reply["choices"][0]["message"]["content"].strip()
        if text.startswith("```"):
            text = text.strip("`").removeprefix("json").strip()
        items = json.loads(text)["remediations"]
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError):
        return None
    if not isinstance(items, list) or len(items) != len(facts) or not all(isinstance(s, str) for s in items):
        return None
    cleaned = [" ".join(certificate.sanitize_text(s).split())[:400] for s in items]
    return cleaned if all(len(s) >= 15 for s in cleaned) else None


def remediate(flags: list[dict[str, str]], generated=None, *, use_groq: bool = True) -> list[dict[str, Any]]:
    """A remediation per flag, in the same order."""
    templates = [template_remediation(f, generated) for f in flags]
    fixes = [changes for changes, _ in templates]
    sentences = groq_sentences(groq_facts(flags, fixes)) if use_groq else None
    out = []
    for i, (changes, text) in enumerate(templates):
        # A sentence the sanitizer had to redact is no longer useful: use the template for that flag.
        usable = sentences is not None and "[redacted]" not in sentences[i]
        out.append({"summary": sentences[i] if usable else text, "config_change": changes,
                    "generated_by": "groq" if usable else "template"})
    return out


def apply_config_changes(architecture: dict[str, Any], remediations: list[dict[str, Any]]) -> dict[str, Any]:
    """The architecture JSON with every catalog config change applied (for "fix and re-analyse")."""
    fixed = json.loads(json.dumps(architecture))
    by_name = {}
    counters: dict[str, int] = {}
    for item in fixed["services"]:
        counters[item["type"]] = counters.get(item["type"], 0) + 1
        name = (item.get("config") or {}).get("name") or f"{item['type'].replace('_', '-')}-{counters[item['type']]}"
        by_name[name] = item
    for rem in remediations:
        for change in rem["config_change"]:
            if "service" in change and change["service"] in by_name and change["type"] in CATALOG:
                by_name[change["service"]].setdefault("config", {})[change["field"]] = change["to"]
    return fixed
