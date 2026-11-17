# Lambda Function Generator

A generator for AWS Lambda functions that an organisation could trust, built as a learning project for cloud, cloud security and DevSecOps work. A requester describes a function; Claude Code interviews them until it is fully specified, then writes the function, its AWS SAM template and its tests. Deterministic scanners, two AI reviewers and a human then check it before it is signed and deployed.

The security controls are designed not to depend on a language model behaving well. A model can propose and review, but it cannot approve, deploy or clear another reviewer's finding. Every generated function must pass `lfg policy-check`, a deterministic checker that compares the function's spec with its template against a catalogue of rules.

Most of this is still a design. See [Current status](#current-status) for what exists today.

## The pipeline

This is the target design, from section 5 of the [design document](docs/superpowers/specs/2026-11-16-lambda-function-generator-design.md). Only the checker (`lfg validate-spec` and `lfg policy-check`) is built so far.

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

## Current status

The project is built in seven plans. Each leaves working, tested software and releases the labs that depend on it.

| Plan | Builds | Labs | Status |
|---|---|---|---|
| 1 | Spec schema, rule catalogue, policy checker, lab tooling | 00, 01, 02 | Built |
| 2 | Two hand-written reference functions, scanner configuration, PR static-checks workflow | 03, 05 | Designed, not built |
| 3 | `/new-lambda` and `/fix-findings` skills, hook, findings schema, the two AI review jobs, publish job, gate | 06, 07, 08 | Designed, not built |
| 4 | Terraform bootstrap, deploy workflow, signing, bill of materials, provenance, tamper detection and runbook | 04, 09, 10, 11 | Designed, not built |
| 5 | Evidence pack, reviewer benchmark, Codex Security workflow | 12, 13, 14 | Designed, not built |
| 6 | S3, SQS and HTTP triggers with their rules | 15, 16 | Designed, not built |
| 7 | Architecture and cost documents, stretch-lab briefs, final README pass | Stretch | Designed, not built |

Nothing has been deployed to AWS, and no AI review has run in CI yet. What works today, on the `reference-solutions` branch, is the `lfg` command-line tool. On the learner branch the checker is what you write in Lab 02.

- `lfg validate-spec <dir>` checks a `function.spec.yaml` against its JSON Schema.
- `lfg policy-check <dir>` checks the spec and the SAM template against the 24 rules it enforces from the 28 in `standards/rules.yaml` (the other four are for scanners and human review), with recorded risk acceptances for the rules that allow them.
- `lfg labcheck <lab>` runs a lab's acceptance checks.

## How to start

Start with [Lab 00](labs/00-workstation/README.md). It sets up WSL2 with Ubuntu, installs every tool, signs you in to AWS with a non-root identity and puts spending guardrails in place. Every command in every lab is bash.

If you already have a Linux shell with Python 3.12 or later, the project installs like this:

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
pip install -e ".[dev]"
```

```bash
lfg labcheck --list
```

On `reference-solutions` you can also run the checker on the compliant example function:

```bash
lfg policy-check tests/lfg/fixtures/good
```

## Labs

Each lab has a brief (goal, why it matters, research questions, tasks, hints, acceptance, debrief, interview questions, exam mapping and a boss challenge), skeleton files for the learner to complete, and acceptance checks run with `lfg labcheck <number>`. A lab's brief is written when the plan that builds it is.

| Lab | Topic | Status |
|---|---|---|
| 00 | Workstation (WSL2, tooling), AWS CLI sign-in, budget alarm, verify the facts marked unverified | Available: [brief](labs/00-workstation/README.md) |
| 01 | Threat model the generator before building it (data flow diagram, STRIDE) | Available: [brief](labs/01-threat-model/README.md) |
| 02 | Function spec schema and policy-as-code checker | Available: [brief](labs/02-spec-and-policy/README.md) |
| 03 | Hand-write one secure Lambda function and SAM template, with no AI | Not yet written (Plan 2) |
| 04 | Terraform bootstrap: OIDC, deploy roles, permissions boundary | Not yet written (Plan 4) |
| 05 | Scanner pipeline: pinned actions, least-privilege tokens | Not yet written (Plan 2) |
| 06 | The `/new-lambda` skill and its hook | Not yet written (Plan 3) |
| 07 | Claude reviewer in CI: structured findings, injection hardening, measured cost | Not yet written (Plan 3) |
| 08 | Codex cross-reviewer, gate script, `/fix-findings` loop | Not yet written (Plan 3) |
| 09 | Deploy pipeline: dev, approval, prod | Not yet written (Plan 4) |
| 10 | Signing, bill of materials, provenance | Not yet written (Plan 4) |
| 11 | Tamper detection and triage runbook | Not yet written (Plan 4) |
| 12 | Evidence pack | Not yet written (Plan 5) |
| 13 | Reviewer benchmark and injection tests | Not yet written (Plan 5) |
| 14 | Codex Security gated scan | Not yet written (Plan 5) |
| 15 | Phase 2 triggers: S3 and SQS | Not yet written (Plan 6) |
| 16 | Phase 3 trigger: HTTP | Not yet written (Plan 6) |
| Stretch | A third AI reviewer or red team; automatic fixing in CI; two AWS accounts; a second runtime | Not yet written (Plan 7) |

Beyond the labs, [the learning roadmap](docs/learning-roadmap.md) lists what to study next, in priority order, and maps each lab to the AWS Solutions Architect Associate exam domains.

## Repository layout

What exists today:

```
labs/                  lab briefs, skeletons and acceptance checks; manifest.yaml lists them
standards/             the secure Lambda standard and its machine-readable rule catalogue
schemas/               the function spec JSON Schema
tools/lfg/             the lfg command-line tool: validate-spec, policy-check, labcheck
tools/dev/             maintainer scripts, such as generating the learner branch
tests/                 unit tests; the seven tests/lfg/ files listed in labs/manifest.yaml check Lab 02
docs/                  the design, the plans, the threat model and the learning roadmap
```

Later plans add `.claude/` (skills and hook settings), `.github/` (workflows and reviewer prompts), `functions/` (generated functions), `benchmark/` (reviewer benchmark) and `infra/bootstrap/` (Terraform), as section 6 of the design describes.

## Security note

The reviewer benchmark added in Plan 5 will contain deliberately vulnerable Lambda functions and prompt-injection fixtures under `benchmark/fixtures/`. They exist to measure what each reviewer catches. They are never to be deployed, and the deploy workflow will exclude them. Do not copy code from them.

This repository is public. No secrets, AWS account IDs or email addresses are committed; they belong in a password manager or in untracked files.

## Authorship

The design, the lab track (briefs, skeletons and acceptance checks) and the reference solutions on the `reference-solutions` branch were written by an AI coach (Claude). The design records Pratik's decisions and marks the calls the coach made on its own. Lab work merged to `main` is Pratik's own.

Branches:

- `reference-solutions`: the complete solution for every lab written so far. Read a lab's reference only after finishing the lab.
- `claude/youthful-sagan-mt8uqi`: the learner branch, generated from the reference by replacing each lab's files with skeletons. Lab work starts here and reaches `main` through pull requests Pratik opens.
- `main`: Pratik's completed work.
