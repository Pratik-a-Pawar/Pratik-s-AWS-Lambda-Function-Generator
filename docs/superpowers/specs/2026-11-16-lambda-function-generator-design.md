# Lambda Function Generator: Design

- **Date:** 2026-11-16
- **Status:** Draft, awaiting Pratik's approval
- **Author:** Vanilla (AI coach), from decisions Pratik made in the design conversation

Items marked **(Pratik)** were decided by Pratik. Items marked **(Vanilla's call)** were filled in by the coach and are open to correction. Items marked **(unverified)** could not be checked against a primary source and must be confirmed during the build.

---

## 1. Intent

Build an on-demand generator for AWS Lambda functions that an organisation could trust:

1. It interviews the requester until the function is fully specified.
2. Claude Code writes the function, its infrastructure template and its tests.
3. Deterministic scanners, then Claude, then OpenAI Codex review it. Codex also reviews Claude's review.
4. Claude Code fixes what the reviews found.
5. A human approves, and the function is deployed to AWS on a schedule or event trigger.

**Why (Pratik):** this is a learning project and a portfolio piece for cloud, cloud security and DevSecOps roles in Dublin. Pratik builds it himself, lab by lab, with the coach teaching and reviewing. It must demonstrate four things equally: cloud engineering fundamentals, security engineering, AI-assisted engineering with AI security, and DevSecOps pipeline design.

## 2. Goals, non-goals, anti-goals

**Goals**

- A working end-to-end pipeline from request to deployed, signed Lambda function.
- Security controls that do not depend on an LLM behaving well.
- Measured evidence of what each reviewer actually catches.
- A lab track that Pratik completes by writing the core himself.
- Total running cost that fits $10 Anthropic credit, $10 OpenAI credit and the AWS free tier.

**Non-goals**

- A web UI or hosted service.
- Languages other than Python in the core build.
- Multi-account AWS Organizations (stretch lab).
- Gemini in the pipeline (designed for, built later as a stretch lab) **(Pratik)**.
- Automatic fixing inside CI (stretch lab) **(Pratik)**.

**Anti-goals: these make the project a failure even if it runs**

- An LLM can approve, deploy, or clear another reviewer's finding.
- An AI agent in CI holds write access to the repository or AWS credentials.
- Long-lived AWS access keys stored in GitHub.
- A generated function can be given more permission than the account-level boundary allows.
- Pratik cannot explain a component because it was handed to him finished.
- The README claims authorship that is not true.

## 3. Constraints

| Constraint | Source |
|---|---|
| Pratik writes the core; the coach supplies briefs, skeletons, checks and reference solutions | Pratik |
| Claude Pro subscription for local Claude Code; $10 Anthropic API credit for CI | Pratik |
| OpenAI: $10 API credit only, no paid ChatGPT plan | Pratik |
| One hardened personal AWS account, region `eu-west-1` (region is Vanilla's call) | Pratik |
| One public GitHub repository; generated functions live in it under `functions/` | Pratik |
| Windows laptop without WSL today; Lab 00 installs WSL2 and all lab commands are bash | Pratik / Vanilla's call |
| 10+ hours a week | Pratik |
| The coach cannot reach Pratik's AWS account or API keys, so AWS and live-LLM steps in the reference solutions are untested until Pratik runs them | Fact |

## 4. Approaches considered

### 4.1 Where the generator runs

| Option | Trade-off | Outcome |
|---|---|---|
| Claude Code locally + GitHub Actions | Real conversational interview; CI does review and deploy; mirrors team practice | **Chosen (Pratik)** |
| GitHub-only via issue form | Nothing to install, but the interview becomes a static form and every step spends API credit | Rejected |
| Custom Python app calling both APIs | Full control, but reinvents Claude Code and Codex and costs the most | Rejected |

### 4.2 The OpenAI reviewer

| Option | Trade-off | Outcome |
|---|---|---|
| Codex cross-review on every PR + Codex Security on demand before prod | Cheap cross-review every time; the real Codex Security product used where it matters, under a hard cost cap | **Chosen (Pratik)** |
| Codex Security on every PR | Closest to the original wording, but it is a scanner that cannot review Claude's review, its per-scan cost is unknown, and some requests need "Trusted Access for Cyber" | Rejected |
| Codex cross-review only | Cheapest, but drops the Codex Security product entirely | Rejected |

### 4.3 Who applies fixes

| Option | Trade-off | Outcome |
|---|---|---|
| Local `/fix-findings` command on Claude Pro | No API spend, human in the loop, no AI agent with write access in CI | **Chosen (Pratik)** |
| Auto-fix inside GitHub Actions | Fully automatic, but spends credit per round and gives an agent write access where prompt injection is the main risk | Stretch lab |
| Both, switchable | Most to build and secure | Rejected |

### 4.4 Infrastructure as code

Terraform for the one-time account bootstrap; AWS SAM for each generated function **(Pratik)**. SAM-only, Terraform-only and CDK were considered and rejected: the split teaches both tools and keeps the generated artefact small and scannable.

### 4.5 Deployment gate

Scanners, both LLM reviews and a human approval **(Pratik)**. "LLM reviews only" was rejected because two models can agree and both be wrong; "auto-deploy" was rejected because nobody stands behind a fooled model.

## 5. Architecture

```
LOCAL (Claude Code on Claude Pro)
  /new-lambda
    interview ──► functions/<name>/function.spec.yaml      (single source of truth)
    generate  ──► src/app.py, template.yaml, tests/, events/
    local hook ─► lfg validate-spec + lfg policy-check      (deterministic, not a prompt)
    branch + pull request
        │
        ▼
GITHUB ACTIONS: pr-checks.yml  (pull_request, same-repo branches only)
  job 1  static     ruff, bandit, semgrep, pip-audit, gitleaks, cfn-lint, checkov,
                    sam validate, lfg validate-spec, lfg policy-check, pytest
  job 2  claude     read-only review ──► findings.claude.json        (needs job 1 green)
  job 3  codex      reads code + Claude findings ──► findings.codex.json
  job 4  publish    no LLM, no secrets: PR comment + SARIF to code scanning
  job 5  gate       lfg gate: blocks on unresolved high/critical
        │
        ▼
LOCAL  /fix-findings  ──► fix, push, pipeline re-runs (maximum 2 fix rounds)
        │
        ▼  merge to main (branch protection: gate must pass)
GITHUB ACTIONS: deploy.yml
  build ► SBOM ► sign (AWS Signer) ► attest ► deploy DEV (OIDC role) ► smoke test
        ► [optional Codex Security scan] ► Pratik approves ► deploy PROD (separate OIDC role)
        ► evidence pack to artefact + S3

AWS (eu-west-1)
  Terraform bootstrap: OIDC provider, deploy roles, CloudFormation execution roles,
  permissions boundary, signing profile + code signing config, artefact and evidence
  buckets, tamper-detection rule + SNS topic, budget alarm
```

### 5.1 The function spec

`functions/<name>/function.spec.yaml`, validated against `schemas/function-spec.schema.json`. The interview fills it in; everything else is generated from it. It is general-purpose from day one **(Pratik)**, even though trigger types are enabled in phases.

Fields: `name`, `purpose`, `owner`, `runtime`, `architecture`, `trigger` (`type` and type-specific config), `permissions` (each with `actions`, `resources`, `reason`), `environment` (non-secret values only), `secrets` (references to SSM Parameter Store or Secrets Manager, never values), `timeout`, `memory`, `reserved_concurrency`, `failure_destination`, `log_retention_days`, `data_classification`, `risk_acceptances` (each with `rule_id`, `justification`, `accepted_by`, `expires`).

Runtime defaults to `python3.13` on `arm64` **(Vanilla's call)**. `python3.14` is allowed by the schema; a search result says AWS supports it until June 2029, but the AWS page could not be opened from the coach's session **(unverified)**. Pratik confirms in Lab 00.

### 5.2 Secure Lambda standard and guardrails

`standards/secure-lambda-standard.md` is a catalogue of rules with stable IDs (`LFG-IAM-001` and so on), each mapped to a CWE and, where relevant, to the OWASP Serverless Top 10 and the AWS Well-Architected security pillar. The generator, both reviewers, the policy checker and the benchmark all refer to the same IDs.

Policy is **hard deny-list plus recorded risk acceptance (Pratik)**. Representative rules (the full catalogue is a build deliverable):

| Class | Examples |
|---|---|
| Always refused | `Action: "*"` on `Resource: "*"`; `NotAction`; AWS-managed admin policies; a role without the permissions boundary; hard-coded secrets; secret values in environment variables; a resource policy with `Principal: "*"` and no condition; a deprecated runtime |
| Always required | Log retention set; a failure destination or dead-letter queue for async triggers; pinned dependencies with hashes; structured logging without event payload dumps; input validation of the event |
| Allowed only with a risk acceptance | An HTTP endpoint without gateway-level authentication; write actions that change other resources (auto-remediation); `Resource: "*"` on actions that support resource-level permissions; timeout above 60 seconds; internet egress from a VPC |

Enforcement is deterministic. `lfg policy-check` reads the spec and the SAM template and fails on violations. It runs as a Claude Code hook after generation and again in CI, so the guardrail holds even if the generator's prompt is ignored or bypassed.

### 5.3 The generator

Claude Code project assets in the repository:

- `.claude/skills/new-lambda/SKILL.md`: the interview, then generation from the spec.
- `.claude/skills/fix-findings/SKILL.md`: downloads the findings artefact for the current PR, fixes, runs local checks, commits with a fix-round trailer, pushes.
- `.claude/settings.json`: a hook that runs spec validation and the policy check after files under `functions/` are written.
- `CLAUDE.md`: points Claude at the standard and the spec schema.

The interview asks until every spec field is settled, refuses deny-listed requests with the rule ID and reason, and records risk acceptances for grey-zone requests.

Each generated function is a self-contained directory:

```
functions/<name>/
  function.spec.yaml
  template.yaml          SAM
  src/app.py
  src/requirements.txt   pinned with hashes
  tests/test_app.py
  events/sample.json
  dispositions.yaml      human decisions on findings, if any
  README.md
```

Generated code uses Powertools for AWS Lambda for structured logging and typed event parsing **(Vanilla's call)**.

### 5.4 The review pipeline

**Shared findings format.** Both reviewers must return JSON that validates against `schemas/findings.schema.json`: reviewer, model, commit, and a list of findings with `id`, `rule_id`, `cwe`, `severity`, `confidence`, `file`, `line_start`, `line_end`, `title`, `description`, `evidence`, `recommendation`. The Codex output adds an assessment of every Claude finding (`confirmed`, `disputed` or `needs_context`, with a reason) and a list of findings Claude missed. That assessment is the "review of the review" from the original idea.

**Claude review.** `anthropics/claude-code-action@v1` with a prompt file, a read-only tool allow-list (`Read`, `Glob`, `Grep`), a strict permission mode, a turn cap and `--json-schema`. Model is set by a repository variable, default `claude-opus-5-5` **(Vanilla's call; cost decision is Pratik's, see section 9)**.

**Codex cross-review.** `openai/codex-action@v1` with a prompt file, the read-only safety strategy and `output-schema-file`. It receives the code and Claude's findings file. Model left at the Codex default unless measured cost says otherwise.

**Publishing.** A separate job with no LLM and no API keys posts one PR comment and uploads SARIF to GitHub code scanning. The reviewer jobs have `contents: read` only.

**Gate.** `lfg gate` merges scanner results and both findings files, then:

- fails if any scanner fails;
- fails on any high or critical finding from either reviewer, unless it is fixed or a human has recorded a disposition (`false_positive` or `accepted_risk`, with justification) in `dispositions.yaml`;
- never lets one reviewer's "disputed" verdict clear the other's finding. A model can raise the bar but cannot lower it;
- after two fix rounds with blocking findings still open, fails with an instruction to escalate to a human decision.

**Codex Security.** A manually triggered workflow runs the open-source Codex Security scanner on the diff with a hard `max-cost` (default 1.50 USD) and uploads SARIF. It is advisory by default. A repository variable can make a clean scan mandatory for production once Pratik has confirmed his API account can run it. Reason: the README says some requests need "Trusted Access for Cyber" and does not say which.

### 5.5 Hardening the AI reviewers

Running AI agents in CI on a public repository is a published attack surface (the "PromptPwnd" research; both vendors' security documents say the same). Controls:

1. AI jobs run only for branches in this repository, never forks. GitHub also withholds secrets from fork PRs.
2. PR title, body and comments are never placed in a prompt. Reviewers see files only.
3. Prompts, schemas and the standard are read from the base branch, with the PR head checked out in a subdirectory, so a PR cannot rewrite its own reviewer's instructions.
4. Reviewer jobs are read-only: no write token, no AWS credentials, a tool allow-list, Codex with sudo dropped and a read-only sandbox.
5. Output must validate against the schema or the job fails. Free text from a model is never executed.
6. All third-party actions are pinned to full commit SHAs, with Dependabot keeping them current. Workflow-level `permissions: {}`, with each job granted only what it needs.
7. Expression values reach shell steps through `env:`, never inline.
8. The benchmark includes fixtures that try to talk the reviewer out of reporting, so resistance is measured rather than assumed.

Residual risk, accepted for a single-maintainer repository: a collaborator with write access can alter workflow files in a PR. Mitigation is branch protection, CODEOWNERS on `.github/` and `standards/`, and keeping the deploy credentials behind environment protection.

### 5.6 Deployment

- **Identity.** GitHub Actions assumes AWS roles through OIDC. No access keys exist. Two roles, `lfg-deploy-dev` and `lfg-deploy-prod`, each trusted only for this repository and its own GitHub environment.
- **Least privilege.** Deploy roles can act only on resources named `lfg-<stage>-*` and pass only the matching CloudFormation execution role. Creating a function role is allowed only when the permissions boundary is attached.
- **Stages (Pratik).** One account, two stages. Merge to main deploys to dev automatically after all checks. Prod requires Pratik's approval as a required reviewer on the `prod` GitHub environment, which is free on public repositories.
- **Supply chain (Pratik).** A software bill of materials per function, AWS Signer code signing with a Lambda code signing configuration set to enforce, and a GitHub build provenance attestation.
- **Smoke test.** After the dev deploy the function is invoked with its sample event.

### 5.7 Tamper detection (Pratik)

An EventBridge rule on CloudTrail management events matches changes to `lfg-*` functions and roles (code or configuration updates, permission changes, policy attachment) made by any principal other than the pipeline roles. It publishes to an SNS topic that emails Pratik. A triage runbook in `docs/runbooks/` covers what the alert means, what to check in CloudTrail, and how to contain and recover, with MITRE ATT&CK technique references.

### 5.8 Evidence pack (Pratik)

For every production deploy, `lfg evidence` assembles one record: spec and its hash, commit, scanner results, both reviews, human dispositions and risk acceptances, the approver and time, the signing job, the attestation link and the bill of materials. It is stored as a workflow artefact and in a versioned S3 bucket. CI does not commit it back to the repository, so CI never needs write access.

### 5.9 Reviewer benchmark (Pratik)

`benchmark/fixtures/` holds about ten deliberately vulnerable Lambda functions with a ground-truth file listing the planted flaws by rule ID and location, plus clean controls and prompt-injection fixtures. `lfg bench` runs the scanners (free) and, when asked, both AI reviewers (spends credit), then reports per-reviewer recall and false positives and what the cross-review added over a single review. Results are written to `benchmark/results/`.

The sample is small and model output varies run to run, so results are reported as indicative, with the run count stated. Fixtures are never deployed and are excluded from the deploy paths.

### 5.10 Reference functions

Two functions the pipeline is proved with **(Vanilla's call)**, both free to run:

1. `iam-key-age-audit`: scheduled; reports IAM access keys older than a threshold.
2. `sg-open-ingress-responder`: triggered by the CloudTrail event for a security group rule opened to the internet; notifies, with automatic revoke available only under a recorded risk acceptance.

A GuardDuty-finding responder is offered as an optional extra because GuardDuty is charged after its 30-day trial.

### 5.11 Trigger phases (Pratik)

| Phase | Triggers | Notes |
|---|---|---|
| 1 | Schedule (EventBridge Scheduler), EventBridge event pattern | Proved with the reference functions |
| 2 | S3 event, SQS queue | Adds partial-batch failure handling and idempotency rules |
| 3 | HTTP (API Gateway HTTP API) | Adds authentication, request validation and throttling rules |

The project is complete when all three phases work.

## 6. Repository layout

```
.claude/                 skills, hook settings
.github/workflows/       pr-checks, deploy, codex-security, benchmark
.github/prompts/         reviewer prompts
standards/               secure-lambda-standard.md
schemas/                 function-spec and findings JSON Schemas
tools/lfg/               Python CLI: validate-spec, policy-check, gate, evidence, bench, labcheck
functions/               generated functions
benchmark/               fixtures, ground truth, results
infra/bootstrap/         Terraform
labs/                    lab briefs and acceptance checks
docs/                    architecture, threat model, learning roadmap, cost, runbooks
```

## 7. Learning track

**Format (Pratik):** each lab has a brief, skeleton files with TODO markers, and acceptance checks. Reference solutions for every lab are written up front on a separate branch.

Each brief contains: the goal; why it matters from first principles; questions to research (questions, not answers); tasks; hints in collapsed sections; the acceptance command; debrief questions; interview questions; and a mapping to AWS Solutions Architect Associate domains. Acceptance checks are run with `lfg labcheck <number>`. Some checks need Pratik's AWS account and run only on his machine.

| Lab | Topic |
|---|---|
| 00 | Workstation (WSL2, tooling), AWS CLI sign-in, budget alarm, verify the runtime facts marked unverified |
| 01 | Threat model the generator before building it (data-flow diagram, STRIDE) |
| 02 | Function spec schema and policy-as-code checker |
| 03 | Hand-write one secure Lambda and SAM template, with no AI |
| 04 | Terraform bootstrap: OIDC, deploy roles, permissions boundary |
| 05 | Scanner pipeline: pinned actions, least-privilege tokens |
| 06 | The `/new-lambda` skill and its hook |
| 07 | Claude reviewer in CI: structured findings, injection hardening, measure cost |
| 08 | Codex cross-reviewer, gate script, `/fix-findings` loop |
| 09 | Deploy pipeline: dev, approval, prod |
| 10 | Signing, bill of materials, provenance |
| 11 | Tamper detection and triage runbook |
| 12 | Evidence pack |
| 13 | Reviewer benchmark and injection tests |
| 14 | Codex Security gated scan |
| 15 | Phase 2 triggers: S3 and SQS |
| 16 | Phase 3 trigger: HTTP |
| Stretch | Gemini as third reviewer or red team; auto-fix in CI; two AWS accounts; a second runtime |

Lab 03 comes before the generator on purpose **(Vanilla's call)**: Pratik should know what a good function looks like before judging a generated one.

**Honest timeline:** at 10+ hours a week this is 8 to 10 weeks, not the 3 to 4 weeks first estimated, because four upgrades were moved into the core build.

**Branches.** Labs, skeletons and checks are developed on `claude/youthful-sagan-mt8uqi` and reach `main` by a pull request Pratik opens. Reference solutions live on a `reference-solutions` branch. The coach needs Pratik's explicit go-ahead to push that second branch.

**Build order for the coach:** write the reference solution first and test what can be tested without AWS, then derive each skeleton by removing the core logic, and confirm each acceptance check fails on the skeleton and passes on the reference.

**Authorship (Vanilla's call):** the README states plainly that the lab track, checks and reference branch were written by an AI coach and that the work on `main` is Pratik's.

## 8. Verification

| Can be verified in the coach's session | Cannot, until Pratik runs it |
|---|---|
| Unit tests for `lfg`; schema validation; policy checks against good and bad templates; scanners on the reference functions; `cfn-lint`; workflow linting; `terraform validate` if Terraform installs | Any AWS deploy; OIDC role assumption; code signing; the tamper alert firing; live Claude and Codex runs in CI; Codex Security access and cost |

The reference branch lists each unverified step with the command Pratik runs to confirm it.

## 9. Cost

**Claude review model.** Prices from Anthropic's model table (cached 2026-11-03): Opus 5.5 at $4 input and $20 output per million tokens; Sonnet 5.5 at $2 and $10. A review of one small function is estimated at roughly $0.15 to $0.40 on Opus 5.5 and about half that on Sonnet 5.5. This is an estimate, not a measurement; Lab 07 measures it. Opus 5.5 is the default because the review is the security-critical step. The model is a repository variable, and the choice is Pratik's.

**OpenAI.** Codex cross-review cost per run is unknown **(unverified)**; Lab 08 measures it. Codex Security is capped per run by `max-cost`.

**Spend controls.** AI jobs run only after scanners pass, only when files under `functions/` change, and not on draft PRs. Superseded runs are cancelled. The benchmark and Codex Security run only on manual trigger. Pratik sets a spend limit in the Anthropic Console and a project budget in the OpenAI dashboard.

**AWS.** Lambda, EventBridge, SNS email, Signer for Lambda and the first CloudTrail management trail fall in free allowances at this scale; S3 storage is cents. A budget alarm is set in Lab 00.

## 10. Unverified items

1. `python3.14` availability and dates on Lambda (search snippet only).
2. The exact IAM trust-policy condition format for GitHub OIDC (AWS and GitHub documentation were unreachable from the coach's session).
3. `codex exec` flags beyond what the `openai/codex-action` README states.
4. Whether a plain pay-as-you-go OpenAI account can run Codex Security scans, and what a diff scan costs.
5. The current default model of `openai/codex-action`.

## 11. Smaller calls made by the coach

- `lfg` is the project's command-line tool, short for Lambda Function Generator.
- `/fix-findings` fetches the findings artefact with the GitHub CLI, and counts fix rounds with a commit trailer that `lfg gate` reads.
- Terraform state lives in an S3 bucket with native lock files, created in Lab 04. The alert email address and account ID are Terraform variables in an untracked file, never committed.
- Anthropic's separate `claude-code-security-review` action is not used: its README says it is not hardened against prompt injection and its default model is old. The Claude review uses `claude-code-action` with this project's own prompt and schema.

## 12. Left to the builder

The full rule catalogue; the exact reviewer prompts; scanner versions and rule sets; the commit SHAs to pin; Terraform module structure; the implementation of each acceptance check; fixture content for the benchmark; the wording of each lab brief.

## 13. Sources

- OpenAI Codex Security CLI and Action: https://github.com/openai/codex-security
- OpenAI Codex Security announcement: https://openai.com/index/codex-security-now-in-research-preview/
- OpenAI Codex GitHub Action and its security notes: https://github.com/openai/codex-action
- Claude Code GitHub Action, usage and security: https://github.com/anthropics/claude-code-action and https://code.claude.com/docs/en/github-actions
- Claude Code headless mode: https://code.claude.com/docs/en/headless
- Claude Code security review action: https://github.com/anthropics/claude-code-security-review
- PromptPwnd research (read through search summaries only): https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents
- AWS Lambda runtimes (search snippet only): https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
- GitHub deployment environments (search snippet only): https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
