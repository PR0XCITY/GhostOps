# GhostOps policy rules (OPA / Rego v1)

Static security checks on Terraform plan JSON (`terraform show -json <planfile>`).
All files in `ghostops/` share `package ghostops`. Requires the `opa` binary (1.x).

| Rule | Decision | Severity | Fires when |
|---|---|---|---|
| GO-SG-001 | deny | CRITICAL | Ingress from `0.0.0.0/0` or `::/0` reaches port 22 (SSH) or 3389 (RDP). Checks `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`; protocol `-1` counts as every port. |
| GO-IAM-001 | deny | CRITICAL | An IAM policy (managed or inline role/user/group) has an `Allow` statement with Action `*` and Resource `*`. |
| GO-S3-001 | deny | HIGH | `aws_s3_bucket_acl` (or legacy `aws_s3_bucket.acl`) is `public-read` or `public-read-write`. |
| GO-RDS-001 | deny | HIGH | `aws_db_instance.storage_encrypted` is not `true` (false, unset or unknown). |
| GO-DEL-001 | warn | MEDIUM | Any managed resource is deleted, including replacements. |

Only resources this plan creates or updates are judged; unchanged (no-op) resources and data sources are ignored.

## Output

`data.ghostops.result` = `{"deny": [...], "warn": [...]}`; each finding is
`{"rule_id", "severity", "address", "message"}`.

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
