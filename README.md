# GhostOps

**A safety layer between an AI coding agent and a real cloud account.**
GhostOps takes a Terraform plan, checks it for security and cost risk, replays it on a free
local AWS emulator, and issues a signed **Risk Certificate**. Low-risk changes are
auto-approved; anything risky is blocked until a human approves or denies it.

College Cloud Architecture Design project. Everything here runs locally and is free:
no real AWS credentials, no paid services.

![Certificates](docs/screenshots/home.png)

## The problem

AI coding agents can now write and apply infrastructure-as-code. A single plausible-looking
Terraform change can open SSH to the whole internet, grant `Action: "*"` on `Resource: "*"`,
make a bucket public, or quietly add monthly cost, and `terraform plan` output is long enough
that a tired human skims past it. Asking the agent "is this safe?" is not a control.

GhostOps puts a deterministic, auditable gate in that path: every plan gets the same checks,
the result is a tamper-evident certificate, and a human decides whenever the risk is real.

## Architecture

```mermaid
flowchart LR
    agent["AI agent / engineer<br/>terraform plan + show -json"] --> api["GhostOps API<br/>FastAPI · CLI"]

    subgraph analysis["Analysis of one plan"]
        parser["Plan parser<br/>normalise resource changes"]
        opa["OPA / Rego rules<br/>static security checks"]
        graph["NetworkX blast radius<br/>before/after graph diff"]
        shadow["Shadow run<br/>apply on MiniStack, then reset"]
        cost["Infracost<br/>monthly cost delta"]
    end

    api --> parser
    parser --> opa
    parser --> graph
    parser --> shadow
    parser --> cost

    opa --> cert["Risk Certificate<br/>verdict + HMAC-SHA256 signature"]
    graph --> cert
    shadow --> cert
    cost --> cert
    cert -. "sanitized rule ids, resource types, severities" .-> groq["Groq LLM<br/>2-3 sentence explanation"]
    groq -.-> cert

    cert --> db[("SQLite<br/>certificates + append-only audit log")]
    db --> dash["Next.js dashboard"]
    dash -- "approve / deny (recorded, never applied)" --> db
```

| Stage | What it does |
|---|---|
| Plan parser (`backend/app/plan_parser.py`) | Normalises `terraform show -json` into create / update / delete / replace / no-op changes. Unknown actions are an error, never ignored. |
| Policy engine (`backend/rules/`, `app/policy_engine.py`) | Rego v1 rules run by the `opa` binary. Fails closed: if OPA cannot run, the plan is blocked. |
| Blast radius (`app/blast_radius.py`) | Builds before/after resource graphs (references + matching ids/ARNs) and reports what becomes reachable from `0.0.0.0/0` and which IAM permissions widen. |
| Shadow run (`app/shadow.py`) | Copies the Terraform directory, forces the AWS provider onto MiniStack with fake keys (override file + scrubbed environment), applies on a freshly reset MiniStack, records the resulting resources, resets again. |
| Cost delta (`app/cost.py`) | Prices the before and after states with Infracost and reports the monthly change per resource. Anything it cannot price is `null` with a reason, never a guess. |
| Certificate (`app/certificate.py`) | Combines everything, decides the verdict, gets an explanation from Groq (sanitized input, template fallback) and signs it with HMAC-SHA256. |
| API, CLI, dashboard | `python -m app.server`, `ghostops analyze <plan.json>`, and the Next.js dashboard in `dashboard/`. |

### Rules that exist today

| Rule | Severity | Fires when |
|---|---|---|
| GO-SG-001 | CRITICAL | SSH (22) or RDP (3389) open to `0.0.0.0/0` or `::/0` (inline, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`) |
| GO-IAM-001 | CRITICAL | IAM policy (managed or inline) allows `Action "*"` on `Resource "*"` |
| GO-S3-001 | HIGH | S3 ACL `public-read` / `public-read-write` |
| GO-RDS-001 | HIGH | `aws_db_instance` without `storage_encrypted = true` |
| GO-DEL-001 | MEDIUM (warn) | any resource deleted or replaced |
| GO-EXPOSE-001 | HIGH | graph diff: a resource newly reachable from the internet |
| GO-IAMW-001 | CRITICAL / HIGH / MEDIUM | graph diff: IAM widened to admin / unknown until apply / other widening |
| GO-SHADOW-001 | HIGH | the shadow apply on MiniStack failed or could not run |
| GO-ENGINE-001 | CRITICAL | the OPA engine could not evaluate the plan |

**Verdict:** any CRITICAL or HIGH flag, or a shadow apply that did not succeed, means
`BLOCKED_PENDING_REVIEW`. Otherwise `AUTO_APPROVED`.

## Design principle

**Security detection is static analysis of the plan JSON; MiniStack is only a functional check.**

The OPA rules and the NetworkX graph diff decide whether a change is dangerous, using only
what Terraform says it will do. MiniStack answers a different question: does this plan
actually apply, and what exists afterwards? The verdict never depends on MiniStack being a
perfect copy of AWS. That matters, because it is not (see Limitations).

Other principles that follow from it:

- **Fail closed.** No OPA, no shadow run, an unknown plan action, or an IAM policy that is only
  known after apply all lead to a block or an error, never to silent approval.
- **Never real AWS.** The shadow run strips every `AWS_*` variable, points the credential
  files at empty files and forces all endpoints to `localhost:4566`.
- **Nothing sensitive leaves the machine for the LLM.** Groq receives only rule ids, rule
  titles, resource types, severities and the verdict, never names, values, ARNs or costs.
- **Tamper-evident.** The certificate is signed over every field; editing any value breaks
  `GET /verify/{plan_id}`. Reviewer decisions go to an append-only audit log and are never
  applied to any system.

## Screenshots

| Blocked change | Auto-approved change |
|---|---|
| ![Blocked certificate](docs/screenshots/blocked-detail.png) | ![Auto-approved certificate](docs/screenshots/approved-detail.png) |

The blocked certificate shows the alarm-red blast radius, the resource graph with flagged
nodes, every risk flag, the signature check and the Approve / Deny controls.

## Running it on Windows

### Prerequisites

- Windows 10/11 with PowerShell
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (running)
- Python 3.11+, Node.js 20+, Git
- Terraform: `winget install --id Hashicorp.Terraform -e`
- OPA: `winget install --id open-policy-agent.opa -e`
- Infracost CLI v2 (optional, for costs): https://www.infracost.io/docs/
- A free Groq API key (optional, for explanations): https://console.groq.com/keys

Open a **new** terminal after installing tools so PATH is refreshed.

### Setup (once)

```powershell
git clone <this repo> GhostOps
cd GhostOps
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e "backend[test]"
npm --prefix dashboard install

copy .env.example .env
# put a signing secret in .env:
python -c "import secrets; print('GHOSTOPS_HMAC_SECRET=' + secrets.token_hex(32))"
# optional: add GROQ_API_KEY to .env, then log in to Infracost:
infracost auth login
```

Infracost v2 uses a browser login, not an API key. Without it, `cost_delta` is `null` with a
note. Without a Groq key, the explanation uses a template.

### Run the demo (one command)

```powershell
python scripts\demo.py
```

It checks prerequisites, starts MiniStack (`docker compose up -d`), the API on
http://127.0.0.1:8000 and the dashboard on http://localhost:3000, then runs both demos:

- `demo/bad`: open SSH, an `Action "*"` IAM policy, a public-read bucket, an unencrypted RDS
  instance and an EC2 instance behind the open security group. Expected: **BLOCKED**.
- `demo/good`: a tagged S3 bucket with a CloudWatch alarm. Expected: **AUTO-APPROVED**.

Real output from a cold start:

```text
[ghostops] demo/bad: BLOCKED_PENDING_REVIEW (as expected) in 116s | flags {'CRITICAL': 3, 'HIGH': 5, 'MEDIUM': 0} | shadow applied=True | cost +23.83 USD/month | explanation by groq
[ghostops] demo/good: AUTO_APPROVED (as expected) in 37s | flags {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0} | shadow applied=True | cost +0.10 USD/month | explanation by groq
[ghostops] all demos behaved as expected
```

Services keep running until Ctrl+C. Use `--exit` to stop after the demos, `--no-groq` for
template explanations. Logs are written to `logs/`.

### Analyse your own plan

```powershell
terraform plan -out tf.plan
terraform show -json tf.plan | Out-File -Encoding utf8 plan.json
.venv\Scripts\ghostops.exe analyze plan.json --tf .
```

Exit code 0 = auto-approved, 1 = blocked, 2 = error. The same works through the API
(`POST /analyze` with `plan_path` or an uploaded file) and the dashboard.

### Run all tests (one command)

```powershell
.venv\Scripts\python.exe scripts\test_all.py
```

Backend pytest (unit, API, signing, sanitization, live MiniStack/Infracost/Groq integration),
OPA policy unit tests, dashboard TypeScript and ESLint. The full run takes about 6-7 minutes
(the shadow runs dominate). Add `--fast` to skip the integration tests (under a minute) or
`--build` to include the dashboard production build.

Latest full run:

```text
PASS  Backend tests (pytest)   367.7s  187 passed in 366.52s (0:06:06)
PASS  OPA policy unit tests      0.1s  PASS: 27/27
PASS  Dashboard TypeScript       6.7s  clean
PASS  Dashboard ESLint           6.5s  clean

ALL CHECKS PASSED
```

## Honest limitations

- **MiniStack is young and is not a full AWS replica.** It is a 1.x community emulator. In
  this project, CloudWatch alarms created through the Terraform AWS provider read back without
  their dimensions, period and tags, so a re-plan always shows drift for them. A plan can also
  apply on MiniStack and still fail on AWS (quotas, IAM, region features), or the reverse. This
  is exactly why the shadow run is a functional check only and never decides security.
- **Only the rules listed above exist.** GhostOps does not yet check KMS policies, Lambda URLs,
  public RDS snapshots, EKS, CloudFront, IAM trust policies (who can assume a role), S3 bucket
  ACL grants to specific users, `NotAction` in OPA rules, and much more. "No findings" means
  "none of these rules fired", not "safe".
- **Values known only after apply** (for example a CIDR taken from another resource's output)
  cannot be checked statically. IAM policies of that kind are blocked; other unknowns pass.
- **Blast radius is approximate.** An instance behind an open security group counts as public
  even without a public IP; `count` references link every instance of a resource.
- **Cost is an estimate.** Usage-based items (S3 storage, requests) are priced at zero usage and
  flagged as a lower bound. Each scan sends planned resource attributes to Infracost's service.
- **The explanation comes from an LLM.** Groq's wording varies between runs (the facts it may
  use are fixed and sanitized); if Groq fails, a template is used.
- **Local tool, not a hosted service.** The API binds to 127.0.0.1 with no authentication and
  can read any `.json` path it is given; only one shadow run uses MiniStack at a time.
- **HMAC is symmetric.** Anyone holding `GHOSTOPS_HMAC_SECRET` can create valid certificates.

## Future work

- **Slack approval:** post blocked certificates to a channel with Approve / Deny buttons that
  call the decision endpoint, so reviewers do not need the dashboard.
- **Automated rollback:** after an approved change is applied for real, watch for drift or
  alarms and generate the inverse plan (with its own certificate) to roll back.
- Asymmetric signatures (Ed25519) so certificates can be verified without the signing secret.
- More rules (IAM trust policies, KMS, public snapshots, Lambda function URLs) and per-team
  policy packs.
- A CI integration that fails a pull request when its plan would be blocked.

## Repository layout

```text
backend/            FastAPI service, analysis pipeline, Rego rules, tests
  app/              plan_parser, policy_engine, blast_radius, shadow, cost, certificate, api, cli
  rules/ghostops/   Rego v1 policies (see rules/README.md)
  tests/            pytest suite, Rego unit tests, plan JSON fixtures
dashboard/          Next.js 16 + TypeScript + Tailwind v4 dashboard
demo/               bad and good Terraform demos, fixture generator, sample certificates
docs/screenshots/   dashboard screenshots
scripts/            demo.py (one-command demo), test_all.py (one-command test suite)
docker-compose.yml  MiniStack
```
