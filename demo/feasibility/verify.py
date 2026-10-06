"""Phase 0: confirm the feasibility resources really exist in MiniStack.

Queries MiniStack directly with boto3 (independent of Terraform state) and
prints PASS/FAIL per resource type. Exit code is non-zero if any check fails.
"""

import json
import os
import sys
from urllib.parse import unquote

import boto3

ENDPOINT = os.environ.get("MINISTACK_ENDPOINT_URL", "http://localhost:4566")
SG_NAME = "ghostops-feasibility-ssh-open"
POLICY_NAME = "ghostops-feasibility-admin-star"
BUCKET = "ghostops-feasibility-bucket"


def client(service):
    # Hard-coded dummy creds: never pick up a real AWS profile from the environment.
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def check_security_group():
    ec2 = client("ec2")
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [SG_NAME]}]
    )["SecurityGroups"]
    if len(groups) != 1:
        return False, f"expected 1 security group named {SG_NAME}, found {len(groups)}"
    sg = groups[0]
    print(f"  GroupId={sg['GroupId']} VpcId={sg.get('VpcId')}")
    for perm in sg["IpPermissions"]:
        cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
        print(f"  ingress {perm.get('IpProtocol')} {perm.get('FromPort')}-{perm.get('ToPort')} from {cidrs}")
    open_ssh = any(
        p.get("IpProtocol") == "tcp"
        and p.get("FromPort") == 22
        and p.get("ToPort") == 22
        and any(r["CidrIp"] == "0.0.0.0/0" for r in p.get("IpRanges", []))
        for p in sg["IpPermissions"]
    )
    return open_ssh, "tcp/22 from 0.0.0.0/0 present" if open_ssh else "tcp/22 0.0.0.0/0 rule missing"


def check_iam_policy():
    iam = client("iam")
    policies = [
        p for p in iam.list_policies(Scope="Local")["Policies"] if p["PolicyName"] == POLICY_NAME
    ]
    if len(policies) != 1:
        return False, f"expected 1 policy named {POLICY_NAME}, found {len(policies)}"
    pol = policies[0]
    print(f"  Arn={pol['Arn']} DefaultVersionId={pol['DefaultVersionId']}")
    version = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
    doc = version["PolicyVersion"]["Document"]
    if isinstance(doc, str):  # real AWS returns URL-encoded JSON; boto3 usually decodes it
        doc = json.loads(unquote(doc))
    print(f"  Document={json.dumps(doc)}")
    statements = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]
    star = any(
        s.get("Effect") == "Allow" and s.get("Action") == "*" and s.get("Resource") == "*"
        for s in statements
    )
    return star, "Allow Action * Resource * present" if star else "wildcard statement missing"


def check_s3_bucket():
    s3 = client("s3")
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    print(f"  Buckets={names}")
    s3.head_bucket(Bucket=BUCKET)  # raises if missing
    return BUCKET in names, "bucket exists" if BUCKET in names else "bucket missing"


def main():
    print(f"MiniStack endpoint: {ENDPOINT}")
    failed = False
    for label, fn in [
        ("aws_security_group", check_security_group),
        ("aws_iam_policy", check_iam_policy),
        ("aws_s3_bucket", check_s3_bucket),
    ]:
        print(f"\n[{label}]")
        try:
            ok, msg = fn()
        except Exception as exc:  # report any API error as a FAIL, not a crash
            ok, msg = False, f"{type(exc).__name__}: {exc}"
        print(f"  {'PASS' if ok else 'FAIL'}: {msg}")
        failed |= not ok
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
