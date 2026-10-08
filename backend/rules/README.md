# GhostOps policy rules (OPA / Rego v1)

Static checks on Terraform plan JSON (`terraform show -json <planfile>`), grouped by pillar
(security, reliability, cost, performance). Only security findings are `deny`; the other
pillars are advisory `warn`. A LOW security finding (GO-S3-002) is also `warn`.
All files in `ghostops/` share `package ghostops`. Requires the `opa` binary (1.x).

| Rule | Decision | Severity | Fires when |
|---|---|---|---|
| GO-SG-001 | deny | CRITICAL | Ingress from `0.0.0.0/0` or `::/0` reaches port 22 (SSH) or 3389 (RDP). Checks `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`; protocol `-1` counts as every port. |
| GO-IAM-001 | deny | CRITICAL | An IAM policy (managed or inline role/user/group) has an `Allow` statement with Action `*` and Resource `*`. |
| GO-S3-001 | deny | HIGH | `aws_s3_bucket_acl` (or legacy `aws_s3_bucket.acl`) is `public-read` or `public-read-write`. |
| GO-RDS-001 | deny | HIGH | `aws_db_instance.storage_encrypted` is not `true` (false, unset or unknown). |
| GO-S3-002 | warn (security) | LOW | S3 bucket with no server-side encryption configuration in code. |
| GO-DEL-001 | warn (reliability) | MEDIUM | Any managed resource is deleted, including replacements. |
| GO-REL-001 | warn (reliability) | MEDIUM | `aws_db_instance.multi_az` is not `true`. |
| GO-REL-002 | warn (reliability) | HIGH | `aws_db_instance.backup_retention_period` is `0`. |
| GO-REL-003 | warn (reliability) | MEDIUM | `aws_s3_bucket` with no enabled `aws_s3_bucket_versioning` (linked by configuration reference or equal bucket name) or legacy inline versioning. |
| GO-REL-004 | warn (reliability) | MEDIUM | Exactly one `aws_instance` created and no `aws_lb` / `aws_alb` / `aws_elb` / `aws_autoscaling_group` in the plan. |
| GO-REL-005 | warn (reliability) | MEDIUM | `aws_dynamodb_table` without `point_in_time_recovery { enabled = true }`. |
| GO-REL-006 | warn (reliability) | LOW | Instances, databases, functions, tables or load balancers created and no `aws_cloudwatch_metric_alarm` in the plan (one finding). |
| GO-COST-001 | warn (cost) | MEDIUM | `aws_instance` tagged `ExpectedCpuPercent` <= 20 with a size other than nano/micro/small. |
| GO-COST-002 | warn (cost) | LOW | gp2: `aws_ebs_volume.type`, `aws_db_instance.storage_type` or an instance root volume. |
| GO-COST-003 | warn (cost) | LOW | Cost-bearing resource with empty `tags` and `tags_all`. |
| GO-PERF-001 | warn (performance) | LOW | `aws_lambda_function.memory_size` <= 128 (unset = 128). |
| GO-PERF-002 | warn (performance) | MEDIUM | `aws_lambda_function.timeout` >= 900. |
| GO-PERF-003 | warn (performance) | MEDIUM | `aws_dynamodb_table` PROVISIONED with no `aws_appautoscaling_target` for it. |

Only resources this plan creates or updates are judged (companions such as a versioning
config or an alarm may be unchanged); unchanged (no-op) resources and data sources are ignored.

## Output

`data.ghostops.result` = `{"deny": [...], "warn": [...]}`; each finding is
`{"rule_id", "pillar", "severity", "address", "message"}`.

## Running

From `backend/`:

```powershell
# by hand
opa eval --format pretty --data rules --input tests/fixtures/bad_plan.json data.ghostops.result

# from Python (validates the plan first, raises PolicyEngineError on any OPA failure)
..\.venv\Scripts\python.exe -m app.policy_engine tests\fixtures\bad_plan.json

# tests: Rego unit tests, then everything through pytest
opa test rules tests/rego -v
..\.venv\Scripts\python.exe -m pytest
```

In code: `from app.policy_engine import evaluate` and `evaluate(plan_dict)`, which returns a list of
`Finding` objects, most severe first. The Python side pipes the plan to
`opa eval --format json --stdin-input --data rules data.ghostops.result`.
`opa` is found via `GHOSTOPS_OPA_BIN`, then `PATH`, then the Windows registry `PATH`.

## Known limits

Values only known after apply (for example a `cidr_blocks` from another
resource's output, or a policy document built from a computed ARN) cannot be
checked statically and are not reported, except RDS encryption, which fails closed.
