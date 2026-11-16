# Threat model: Lambda Function Generator

This is the reference threat model for Lab 01, written by the AI coach from section 5 of the design (`docs/superpowers/specs/2026-11-16-lambda-function-generator-design.md`). Pratik writes his own version in Lab 01 before reading this one.

It describes the system as designed. Only the checker (`lfg validate-spec`, `lfg policy-check` and the rule catalogue in `standards/rules.yaml`) is built so far. The `Status` column says which controls exist and which are still on paper:

- **Built**: the control exists in this repository and has tests. The rule ID or file is named.
- **Partly built**: part of the control is built (named); the rest is designed.
- **Designed**: specified in the design (section named) but not built yet.
- **Accepted**: a residual risk the design accepts on purpose.
- **Open**: no mitigation in the design yet. These are inputs to later labs.

Section numbers such as §5.5 refer to the design document.

## System overview

The generator turns a conversation into a deployed AWS Lambda function, with security checks that do not depend on an LLM behaving well.

1. **Local.** Pratik runs Claude Code on his laptop (inside WSL2). The `/new-lambda` skill interviews him until `functions/<name>/function.spec.yaml` is complete, then writes the handler, the SAM template, tests and a sample event. A Claude Code hook runs `lfg validate-spec` and `lfg policy-check` after files under `functions/` are written (§5.3). He pushes a branch and opens a pull request.
2. **Pull request checks.** `pr-checks.yml` runs on `pull_request` for branches in this repository only (§5.4, §5.5). Job 1 runs deterministic scanners and the policy check. Job 2 runs a read-only Claude review that returns findings as JSON. Job 3 runs a Codex cross-review that reads the code and Claude's findings and assesses each one. Job 4, with no LLM and no secrets, posts a comment and uploads SARIF. Job 5, `lfg gate`, blocks on unresolved high or critical findings.
3. **Fixes.** Locally, `/fix-findings` fetches the findings, fixes and pushes again, at most two rounds (§5.4).
4. **Deploy.** After merge to `main`, `deploy.yml` builds the package, produces a bill of materials, signs it with AWS Signer, attests provenance, and deploys to dev through an OIDC role. Prod needs Pratik's approval on the `prod` GitHub environment and uses a separate OIDC role. An evidence pack is stored as a workflow artefact and in S3 (§5.6, §5.8).
5. **AWS.** A Terraform bootstrap creates the OIDC provider, the deploy and CloudFormation execution roles, the permissions boundary `lfg-function-boundary`, the signing profile and code signing configuration, the artefact and evidence buckets, a tamper-detection rule with an SNS topic, and a budget alarm (§5, §5.7). Region `eu-west-1`.
6. **Runtime.** Each generated function runs under its own role, capped by the permissions boundary, and is triggered by a schedule or an EventBridge pattern (§5.11 phase 1).

## Data flow diagram

Trust boundaries are drawn as `=====` lines. Numbered arrows are the data flows the threats refer to.

```
 [Pratik]
    | (1) interview answers
    v
=========================== TB1: developer machine (Windows + WSL2) ===========================
 Claude Code (/new-lambda) ---(2) prompts + repo files---> [Anthropic API]   (TB3, local use)
    | (3) spec, src, template, tests
    v
 local hook: lfg validate-spec + lfg policy-check
    | (4) git push branch, open PR  (Pratik's GitHub credentials)
=========================== TB2: GitHub (repository + hosted runners) =========================
 Repository: branches, PRs, base-branch prompts/schemas/standard, branch protection, CODEOWNERS
    | (5) pull_request event (same-repo branches only)
    v
 pr-checks.yml
   job 1 static  ---- scanners + policy-check, no secrets
   job 2 claude  ---(6) PR files + base prompt ------> [Anthropic API]   ===== TB3: LLM providers
                 <--(7) findings.claude.json -------- 
   job 3 codex   ---(8) PR files + Claude findings --> [OpenAI API]      =====
                 <--(9) findings.codex.json --------- 
   job 4 publish ---(10) PR comment, SARIF (no LLM, no secrets)
   job 5 gate    ---(11) pass/fail to branch protection
    | (12) merge to main
    v
 deploy.yml: build -> SBOM -> sign -> attest -> deploy dev -> smoke test
             -> [optional Codex Security scan] -> Pratik approves (prod environment) -> deploy prod
    | (13) OIDC token for this repo + environment
=========================== TB4: AWS account (eu-west-1) ======================================
 STS: AssumeRoleWithWebIdentity -> lfg-deploy-dev / lfg-deploy-prod
    | (14) signing job (Signer), package to artefact bucket, CloudFormation change set
    v
 CloudFormation execution role -> lfg-<stage>-<name> function + role (boundary) + log group
    | (15) evidence pack -> evidence bucket (versioned)
 CloudTrail management events -> EventBridge tamper rule -> SNS -> email to Pratik  (16)
------------------------------- function runtime (inside TB4) ---------------------------------
 EventBridge schedule / event pattern ---(17) event---> generated function ---(18) AWS API calls
 generated function ---(19) logs---> CloudWatch Logs
```

## Assets

| Asset | Why an attacker wants it | Where it lives |
|---|---|---|
| Anthropic API key | Spend Pratik's credit; run arbitrary prompts on his account | GitHub Actions secret, available to the Claude review job only |
| OpenAI API key | Same, on the OpenAI account | GitHub Actions secret, available to the Codex jobs only |
| Deploy roles `lfg-deploy-dev`, `lfg-deploy-prod` | Deploy code into the account; the prod role reaches production | AWS IAM, assumable through GitHub OIDC |
| CloudFormation execution roles and the permissions boundary | Create roles and resources; widening the boundary removes the ceiling on every function | AWS IAM, Terraform bootstrap |
| Signing profile and code signing configuration | Sign malicious code so Lambda accepts it, or switch enforcement off | AWS Signer and Lambda, Terraform bootstrap |
| Evidence bucket | Rewrite the record of who approved what | S3, versioned |
| Generated code and its spec | Plant a backdoor that runs with the function's permissions | `functions/<name>/` in the repository, then the deployed package |
| Reviewer prompts, schemas, the standard and `rules.yaml` | Weaken the checks so later changes pass | `.github/prompts/`, `schemas/`, `standards/` on the base branch |
| Pratik's GitHub account and AWS sign-in | Approve prod deploys, change branch protection, act as the administrator | GitHub, IAM Identity Center or IAM |
| CloudTrail logs and the tamper alert | Hide changes made outside the pipeline | AWS account |
| Terraform state | Read resource details; change the bootstrap | S3 state bucket (Lab 04, §11) |

## Trust boundaries

| ID | Boundary | What crosses it | What is trusted on each side |
|---|---|---|---|
| TB1 | Developer machine (Windows laptop, WSL2) | Interview answers in; generated files and `git push` out; prompts and repository files to the Anthropic API | Pratik and his local tools are trusted, but any file the session reads (a cloned repository, a dependency) may carry instructions |
| TB2 | GitHub: repository and GitHub-hosted runners | PR branches in; secrets into specific jobs; findings, comments and SARIF out; OIDC tokens to AWS | The base branch and its workflow files are trusted; PR content is not, even from a same-repository branch |
| TB3 | LLM providers (Anthropic, OpenAI) | Source code and prompts out; findings in | Model output is untrusted data: it must validate against the findings schema and can only raise the bar at the gate |
| TB4 | AWS account (`eu-west-1`) | OIDC tokens and packages in; alerts and evidence out | Only the pipeline roles change `lfg-*` resources; anything else is an alert |
| TB4a | Function runtime inside AWS | Events in; AWS API calls and logs out | The event is untrusted input until the handler validates it |

## Threats

| ID | Component | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|---|
| TM-01 | GitHub OIDC trust (flow 13) | Spoofing | A workflow from another repository, a fork, or a non-prod job in this repository gets an OIDC token that satisfies the prod role's trust policy, because the `sub` condition is too loose, and deploys to prod | Each deploy role trusts only this repository and its own GitHub environment; the trust policy checks `aud` and an exact `sub` (§5.6). Lab 00 Q2 confirms the exact `sub` value | Designed (§5.6); condition format unverified (§10 item 2) |
| TM-02 | Pratik's GitHub account | Spoofing | A stolen GitHub session or personal access token is used to approve a prod deploy or relax branch protection | Prod approval is limited to the required reviewer on the `prod` environment (§5.6), but the attacker would be that reviewer. Account MFA is an operational control the design does not cover | Open |
| TM-03 | Claude review job (flows 6 and 7) | Tampering | Prompt injection in a code comment, docstring, test or sample event in the PR tells the Claude reviewer to report no findings | Reviewers see files only (§5.5 item 2); deterministic scanners and `lfg policy-check` run first and do not read instructions (§5.4 job 1); the gate never lets a reviewer clear a finding (§5.4); a human approves prod (§5.6); injection fixtures in the benchmark measure resistance (§5.5 item 8) | Designed (§5.4, §5.5) |
| TM-04 | Claude and Codex review jobs | Information disclosure | Prompt injection in the PR makes a reviewer agent read and send out a secret, such as its API key or a token from the runner | Tool allow-list `Read`, `Glob`, `Grep`; no shell; no write token and no AWS credentials in reviewer jobs; Codex in a read-only sandbox with sudo dropped (§5.5 item 4); each job gets only the secret it needs | Designed (§5.5) |
| TM-05 | Codex cross-review (flows 8 and 9) | Tampering | The cross-reviewer marks a real Claude finding as "disputed" (by mistake or through prompt injection) and the gate drops it | `lfg gate` never lets one reviewer's "disputed" verdict clear the other's finding; only a human disposition in `dispositions.yaml` clears a finding (§5.4) | Designed (§5.4) |
| TM-06 | Reviewer output parsing | Tampering | Model output that is malformed or carries extra instructions is parsed loosely or executed, and a failing review passes | Output must validate against `schemas/findings.schema.json` or the job fails; free text is never executed (§5.5 item 5) | Designed (§5.5) |
| TM-07 | `pr-checks.yml` trigger | Elevation of privilege | A fork PR runs under `pull_request_target`, or a fork's code is checked out in a job that holds secrets, giving the fork author the API keys | Workflows use `pull_request`; AI jobs run only for branches in this repository (§5.5 item 1); GitHub withholds secrets from fork PRs | Designed (§5.5) |
| TM-08 | Workflow shell steps | Elevation of privilege | A branch name or file name containing shell syntax is expanded inline with `${{ }}` in a `run:` step and executes on the runner | Expression values reach shell steps through `env:` only (§5.5 item 7); PR title, body and comments are never used (§5.5 item 2) | Designed (§5.5) |
| TM-09 | Reviewer prompts and the standard | Tampering | A PR edits `.github/prompts/`, `schemas/` or `standards/` so that its own review uses weaker instructions | Prompts, schemas and the standard are read from the base branch, with the PR head in a subdirectory (§5.5 item 3); CODEOWNERS on `.github/` and `standards/` (§5.5) | Designed (§5.5) |
| TM-10 | Third-party GitHub Actions | Tampering | A tag of a third-party action is moved to malicious code that steals secrets or alters the build | Actions pinned to full commit SHAs, updated by Dependabot; workflow-level `permissions: {}` with per-job grants (§5.5 item 6) | Designed (§5.5) |
| TM-11 | Generated function dependencies | Tampering | A compromised or typo-squatted Python package enters `src/requirements.txt` | Exact pins with hashes, no URL references (LFG-DEP-001 in `lfg policy-check`); `pip-audit` in the static job (§5.4) | Partly built (LFG-DEP-001); pip-audit Designed (§5.4) |
| TM-12 | Generated IAM permissions | Elevation of privilege | The generator, by mistake or misled by prompt injection, grants `Action: "*"`, `NotAction`, a managed admin policy or `Resource: "*"` on a scopable action | LFG-IAM-001, LFG-IAM-002, LFG-IAM-003, LFG-IAM-005, LFG-IAM-007 and LFG-IAM-008 in `lfg policy-check`; the permissions boundary caps whatever slips through (§5.6) | Built (LFG-IAM-001/002/003/005/007/008); boundary policy Designed (§5.6) |
| TM-13 | Generated SAM template | Elevation of privilege | The template adds a resource, property or macro that creates permissions the checker does not model, such as an extra IAM role, a SAM connector or a transform | Allow-lists for resource types, function and event properties, template sections and transforms (LFG-TPL-001, LFG-TPL-002, LFG-TPL-003, LFG-TPL-004); every created role carries the boundary and no external role is allowed (LFG-IAM-004) | Built (LFG-TPL-001 to 004, LFG-IAM-004) |
| TM-14 | Spec and template | Tampering | The template grants actions or uses settings the reviewed spec never declared, so the human approves one thing and another is deployed | Every IAM action must be declared in the spec (LFG-SPEC-001); runtime, architecture, timeout, memory and trigger must match (LFG-SPEC-002) | Built (LFG-SPEC-001, LFG-SPEC-002) |
| TM-15 | Risk acceptances | Elevation of privilege | A requester adds a risk acceptance to waive a deny rule, or one that never expires, to get a dangerous permission through | Only `accept`-class rules can be accepted and an expired acceptance counts as none (LFG-RA-001). `accepted_by` is free text, so who accepted is not verified; PR review and the evidence pack (§5.8) record it | Built (LFG-RA-001); acceptor identity Open |
| TM-16 | Secrets in generated code | Information disclosure | A secret value is placed in an environment variable or hard-coded in the handler, then appears in the console, logs or the public repository | Secret-looking variable names refused (LFG-SEC-001, judges names not values); secrets only as SSM or Secrets Manager references (§5.1); gitleaks for hard-coded secrets (LFG-SEC-002, scanner in §5.4) | Partly built (LFG-SEC-001); LFG-SEC-002 scanner Designed (§5.4) |
| TM-17 | Generated handler logging | Information disclosure | The handler logs whole events, secrets or personal data to CloudWatch Logs | Structured logging with Powertools (§5.3); safe logging rule for reviewers (LFG-COD-002); log retention set (LFG-LOG-001) | Partly built (LFG-LOG-001); LFG-COD-002 is a review rule (Designed, §5.4) |
| TM-18 | Generated handler code | Elevation of privilege | Event data reaches `eval`, a shell or unsafe deserialisation in the handler and runs code with the function's role | No dynamic execution (LFG-COD-003, bandit and semgrep in §5.4); validate the event first (LFG-COD-001, review) | Designed (§5.4; rules LFG-COD-001 and LFG-COD-003 catalogued) |
| TM-19 | Event source of a responder function | Spoofing | A forged or crafted event triggers `sg-open-ingress-responder` to revoke rules or send false alerts | The handler validates the event (LFG-COD-001); automatic revoke needs a recorded acceptance for `ec2:RevokeSecurityGroup*` (LFG-IAM-006); who may put events matching the pattern is to be confirmed in Lab 03 | Partly built (LFG-IAM-006); event validation Designed |
| TM-20 | Deploy roles (flow 14) | Elevation of privilege | A compromised deploy job uses `lfg-deploy-dev` to create a role without the boundary, pass an administrator role, or change resources outside `lfg-dev-*` | Deploy roles act only on `lfg-<stage>-*`, pass only the matching CloudFormation execution role, and may create roles only with the boundary attached (§5.6) | Designed (§5.6) |
| TM-21 | AWS credentials for CI | Information disclosure | Long-lived access keys stored as GitHub secrets leak through a log or a compromised action | No access keys exist; GitHub Actions uses OIDC and short-lived sessions (§5.6; anti-goal in §2) | Designed (§5.6) |
| TM-22 | Deployed function code | Tampering | Someone with AWS access uploads unsigned code to an `lfg-prod-*` function, bypassing the pipeline | Code signing configuration set to enforce (§5.6); tamper detection alerts on changes by any principal other than the pipeline roles (§5.7) | Designed (§5.6, §5.7) |
| TM-23 | Signing profile | Spoofing | Any principal allowed to start signing jobs on the profile signs arbitrary code, which Lambda then accepts as genuine | Not yet specified: restrict use of the signing profile to the deploy roles (Lab 10) | Open |
| TM-24 | Out-of-band changes in AWS | Repudiation | A console or CLI change to an `lfg-*` function or role is made and nobody can say who made it or when | CloudTrail management events feed the tamper rule, which emails Pratik with the principal (§5.7); triage runbook (§5.7) | Designed (§5.7) |
| TM-25 | CloudTrail | Repudiation | An attacker with administrator access stops or deletes the trail, so later changes leave no record and the tamper rule goes quiet | Generated functions cannot hold `cloudtrail:StopLogging` or `cloudtrail:DeleteTrail` without a recorded acceptance (LFG-IAM-006). The tamper rule watches `lfg-*` resources, not the trail itself | Partly built (LFG-IAM-006); trail monitoring Open |
| TM-26 | Prod approvals and dispositions | Repudiation | Nobody can show who approved a prod deploy, which findings were waived, or which spec was deployed | Required reviewer on the `prod` environment (§5.6); dispositions in `dispositions.yaml` in git history (§5.4); evidence pack with spec hash, approver, time and signing job (§5.8) | Designed (§5.4, §5.6, §5.8) |
| TM-27 | Evidence bucket | Repudiation | Evidence records are overwritten or deleted after a deploy | Versioned S3 bucket (§5.8); CI never commits evidence back (§5.8). Deletion protection beyond versioning is not specified | Designed (§5.8); deletion protection Open |
| TM-28 | AI review spend | Denial of service | Repeated pushes, a fix loop or a large diff spend the API credit until reviews stop running | AI jobs run only after scanners pass, only for changes under `functions/`, not on draft PRs; superseded runs cancelled; benchmark and Codex Security manual only (§9); at most two fix rounds (§5.4); provider spend limits (Lab 00) | Designed (§9, §5.4) |
| TM-29 | Generated function at runtime | Denial of service | An event storm or a retry loop invokes the function far more than expected, causing throttling and cost | Reserved concurrency in the spec (§5.1); timeouts above 60 seconds need acceptance (LFG-RUN-002); failure destination for async triggers (LFG-REL-001); budget alarm (§9) | Partly built (LFG-RUN-002, LFG-REL-001); budget alarm set in Lab 00 |
| TM-30 | Code sent to LLM providers (flows 2, 6, 8) | Information disclosure | Source code, findings and anything mistakenly committed are sent to two third-party APIs and kept under their retention terms | Only files are sent, never PR text (§5.5 item 2); no secrets in code (LFG-SEC-001, LFG-SEC-002); the repository is public, so code confidentiality is not claimed | Accepted (public repository) |
| TM-31 | Local Claude Code session (TB1) | Tampering | Prompt injection in a file the local session reads, such as a cloned dependency or a pasted document, steers the generator to add a backdoor or run commands on the laptop | The local hook re-runs the deterministic checks (§5.3) and CI runs them again where the laptop cannot skip them (§5.4); Pratik reviews the diff; Claude Code permission prompts | Partly built (`lfg policy-check`); hook and CI Designed (§5.3, §5.4) |
| TM-32 | Branch protection and workflow files | Elevation of privilege | A collaborator with write access edits a workflow file in a PR to run with secrets or skip the gate | Branch protection, CODEOWNERS on `.github/` and `standards/`, deploy credentials behind environment protection (§5.5) | Accepted (§5.5 residual risk, single-maintainer repository) |
| TM-33 | Terraform state | Information disclosure | The state bucket is readable or writable by more principals than the bootstrap needs, exposing resource details or allowing the bootstrap to be altered | State in S3 with native lock files (§11); access to the state bucket is not yet specified | Designed (§11, Lab 04); access policy Open |

## Top risks

1. **Prompt injection against the AI reviewers (TM-03, TM-04, TM-05).** The reviewers read files an attacker controls, on a public repository, in CI. The design's answer is to keep the LLMs out of every decision that matters: deterministic checks run first, model output is schema-checked data, a reviewer can only raise the bar, and a human approves prod. Until Lab 13 measures it, resistance is assumed, not shown.
2. **A loose OIDC trust policy (TM-01).** One wrong condition lets another workflow or a non-prod job assume the prod deploy role. The exact `sub` format is unverified (§10 item 2), so Lab 00 Q2 and Lab 04 must confirm it against GitHub's documentation and a real token's claims before prod is trusted.
3. **An over-privileged generated function (TM-12, TM-13, TM-14, TM-15).** This is the risk the built checker addresses most directly, and the reason it uses allow-lists. Its stated limits remain: it cannot judge whether a scoped ARN is narrow enough, and `accepted_by` is not verified. The permissions boundary is the backstop and is not built yet.
4. **Supply-chain compromise of the pipeline (TM-10, TM-11, TM-22, TM-23).** A moved action tag, a malicious package or a misused signing profile puts attacker code into a signed, deployed function. SHA pinning, hash-pinned dependencies (LFG-DEP-001, built) and enforced code signing cover most of it; who may use the signing profile is still open.
5. **Changes nobody sees (TM-24, TM-25, TM-27).** If someone changes a function outside the pipeline or turns off CloudTrail, the evidence and the alert both depend on logs the attacker can affect. Tamper detection covers `lfg-*` resources only; watching the trail itself and protecting evidence from deletion are open items for Labs 11 and 12.
