# Learning roadmap

What to learn beyond the labs, in priority order. The labs teach each topic as far as this project needs it; this roadmap says where to go further, and what you should be able to do when you have. It is written by the AI coach and is open to your correction.

How to use it:

- Work down the list, but let the labs set the pace: each topic names the labs that lean on it, so study it just before or alongside them.
- Learn from primary sources: the AWS documentation and the Service Authorization Reference, GitHub's documentation, the HashiCorp Terraform documentation, the OWASP project pages, MITRE ATT&CK and the relevant specifications. The documents are named here, not linked; search for the title on the publisher's own site.
- For the AWS Solutions Architect Associate exam, keep to the two courses you have already chosen. This roadmap does not add any.
- Treat each "be able to" list as a checklist. You know a topic when you can do every item without notes and explain why each step is there.

## 1. IAM policy evaluation

Every rule in Lab 02 and every role in Lab 04 is a prediction of how IAM will decide a request. If you cannot make that prediction yourself, you cannot review a policy, and you cannot tell whether a checker is right.

Be able to:

- Given an identity policy, a permissions boundary, a resource policy and a session policy, predict whether a request is allowed and name the statement that decided it.
- Explain the difference between an explicit deny and an implicit deny, and where each comes from.
- Write a least-privilege policy for a Lambda function from the Service Authorization Reference: the right actions, the narrowest resource ARNs, and condition keys where they help.
- Explain why `iam:PassRole` and the ability to create roles are privilege-escalation risks, and how a boundary condition contains them.
- Read an `AccessDenied` error or CloudTrail event and work out which kind of policy denied it.

Read: the IAM User Guide (policy evaluation logic, policy grammar, permissions boundaries, IAM JSON policy elements); the Service Authorization Reference.

Labs: 02, 04, 09.

## 2. CloudFormation and AWS SAM

The SAM template is what gets deployed, the generator writes it and the checker reads it. SAM also creates resources you never wrote, which is where several checker rules come from.

Be able to:

- Read a SAM template and list everything it will create once the SAM transform has run, including roles and permissions SAM adds on its own.
- Find out how to see the template after the transform, and compare it with what you wrote.
- Explain intrinsic functions, parameters, conditions and macros, and say which of them can change what is deployed after a static check has read the file.
- Use `sam validate`, `sam build` and `sam deploy`, and explain what a change set shows and what a stack rollback undoes.

Read: the AWS SAM Developer Guide (the `AWS::Serverless::Function` reference, event source types, policy templates); the AWS CloudFormation User Guide (template anatomy, intrinsic function reference, macros, change sets).

Labs: 02, 03, 06, 09.

## 3. Python testing

In this project the tests are the lab checks, and the only proof that a security rule works. A table of mutations, each with its expected result, is how you enumerate the ways past a rule.

Be able to:

- Write parametrised pytest tables, fixtures, and tests that use `tmp_path`, `monkeypatch` and `capsys`.
- Test exit codes, exception types and error messages, not only return values.
- Reproduce a bypass as a failing test before fixing it.
- Change one line of your own code to a plausible mistake and see whether any test fails. If none does, write the test that would.
- Test code that calls AWS without calling AWS.

Read: the pytest documentation (fixtures, parametrisation, `monkeypatch`, `tmp_path`); the Python documentation for `unittest.mock`; the botocore documentation on stubbing responses.

Labs: 02, 03, and every lab after.

## 4. GitHub Actions security and OIDC

CI will hold the route into AWS and into two paid AI accounts. A workflow is code that an attacker can try to change, trigger or feed with text.

Be able to:

- Set `permissions` for the workflow and for each job, and explain what the default `GITHUB_TOKEN` can do.
- Explain the difference between `pull_request` and `pull_request_target`, and what a fork's pull request can and cannot reach.
- Pin third-party actions to full commit SHAs and explain why a tag is not enough.
- Recognise script injection through expressions, and pass untrusted values through `env:` instead.
- Configure an AWS role trusted through GitHub's OIDC provider, with a trust policy that admits only one repository and one environment, and explain each condition in it.
- Use environments with required reviewers to protect production credentials.

Read: GitHub's documentation on security hardening for GitHub Actions, OpenID Connect, workflow syntax (`permissions`) and deployment environments; the IAM User Guide on OIDC identity providers and role trust policies.

Labs: 04, 05, 07, 08, 09.

## 5. Terraform state and modules

The account bootstrap (the OIDC provider, deploy roles, permissions boundary and signing setup) lives in Terraform. Its state file describes all of it and can hold sensitive values, so it is a target in its own right.

Be able to:

- Explain what the state file contains, why it is sensitive, and who should be able to read and write it.
- Configure the S3 backend with locking, as the design specifies, and explain what locking prevents.
- Split configuration into modules with clear inputs and outputs.
- Read a plan before applying it, detect drift, and import a resource that was created by hand.
- Keep account IDs and email addresses in an untracked variables file, never in the repository.

Read: the Terraform documentation (state, the S3 backend, modules, sensitive values, import); the AWS provider documentation for the resources you create.

Labs: 04.

## 6. OWASP Serverless Top 10

A shared list of the ways serverless applications go wrong. The secure Lambda standard names a category for several of its rules.

Be able to:

- Name the categories and map each rule in `standards/secure-lambda-standard.md` to one, where one fits.
- Name a category that the policy checker cannot cover, and the control in this project that should.
- Say how old the list is and which parts of it you would weigh differently today, with reasons.

Read: the OWASP Serverless Top 10 project.

Labs: 02, 03, 13.

## 7. OWASP Top 10 for LLM Applications

Two of the pipeline's reviewers are language models that read files an attacker can write. This list is the vocabulary for what can go wrong with them.

Be able to:

- Explain direct and indirect prompt injection, and show where indirect injection enters this pipeline.
- Explain why a model's output must be treated as untrusted input, and how a JSON Schema on that output helps and where it stops helping.
- Design a control that still holds when the model is fooled, and say what it costs.
- Measure a reviewer's resistance to injection with test fixtures instead of assuming it.

Read: the current version of the OWASP Top 10 for LLM Applications (check the category names; they have changed between versions); the security sections of the documentation for the two AI GitHub Actions this project uses.

Labs: 01, 07, 08, 13.

## 8. STRIDE threat modelling

Lab 01 is your first threat model. The skill is doing it quickly and keeping it true as the design changes.

Be able to:

- Draw a data flow diagram with trust boundaries for a new component in under an hour.
- Walk each boundary crossing through the six STRIDE categories and turn each credible threat into a control and a test.
- Keep a threat model current: update it when a lab changes the design, and mark controls honestly as built, designed or open.
- Explain what STRIDE tends to miss, and which other method you would add.

Read: Microsoft's STRIDE material; the OWASP Threat Modeling Cheat Sheet and the OWASP threat modelling project pages.

Labs: 01, and every later lab that changes the design.

## 9. CloudTrail and EventBridge for detection

Preventive controls fail. Lab 11 adds the detective one: an alert when someone changes a function or role outside the pipeline.

Be able to:

- Find in CloudTrail who changed a Lambda function or an IAM role, when, and from where, and read `userIdentity` correctly.
- Explain management events and data events, and which ones this project needs.
- Write an EventBridge pattern that matches the right CloudTrail events and excludes the pipeline's own roles, and route it to SNS.
- Triage an alert: decide whether it is real, contain it, recover, and write down what happened, with MITRE ATT&CK technique IDs where they fit.

Read: the AWS CloudTrail User Guide (event reference, management and data events); the Amazon EventBridge User Guide (event patterns); the MITRE ATT&CK cloud matrix.

Labs: 00 (boss challenge), 11.

## 10. Supply-chain controls: signing, bill of materials, provenance

Each control answers a different question: who produced this and has it changed (signing), what is inside it (a bill of materials), and how and from what was it built (provenance). None of them says the code is safe.

Be able to:

- Explain what each of the three proves and what it does not.
- Pin dependencies to exact versions with hashes, and explain what that stops and what it does not (LFG-DEP-001).
- Set up code signing for Lambda with a code signing configuration that enforces it, and show a deploy of unsigned code being refused.
- Generate a bill of materials for a function and read it.
- Produce and verify a build provenance attestation for an artefact built in GitHub Actions.

Read: the AWS Signer and Lambda code signing documentation; GitHub's documentation on artifact attestations; the SLSA specification; the CycloneDX or SPDX specification.

Labs: 02, 05, 10.

## The labs and the Solutions Architect Associate exam

This mapping is the coach's judgement, not an official AWS mapping. The four domains are Design Secure Architectures, Design Resilient Architectures, Design High-Performing Architectures and Design Cost-Optimized Architectures. Check the current exam guide for the task statements under each.

| Lab | Topic | Domains (coach's judgement) | Exam topics it touches |
|---|---|---|---|
| 00 | Workstation, AWS sign-in, budget alarm | Secure; Cost-Optimized | Root user protection, MFA, IAM Identity Center; AWS Budgets |
| 01 | Threat model | Secure | Identifying risks and the controls that answer them |
| 02 | Spec and policy checker | Secure; Resilient; Cost-Optimized | Least-privilege IAM, permissions boundaries, secrets handling; failure handling for asynchronous invocations; log retention and timeouts |
| 03 | Hand-written secure Lambda function | Secure; Resilient; High-Performing; Cost-Optimized | Execution roles; retries and failure destinations; memory and architecture choices; Lambda pricing |
| 04 | Terraform bootstrap | Secure | Federation with an external identity provider, roles, permissions boundaries, encrypted and versioned S3 buckets |
| 05 | Scanner pipeline | Secure | Mostly outside the exam: CI supply chain and token scope |
| 06 | `/new-lambda` skill and hook | Secure | Mostly outside the exam: guardrails on generated infrastructure |
| 07 | AI reviewer in CI | Secure; Cost-Optimized | Mostly outside the exam: least-privilege CI jobs, measuring cost |
| 08 | Cross-reviewer, gate, fix loop | Secure | Mostly outside the exam |
| 09 | Deploy pipeline: dev, approval, prod | Secure; Resilient | Separate roles per environment; staged deployment and rollback with CloudFormation |
| 10 | Signing, bill of materials, provenance | Secure | Code signing for Lambda |
| 11 | Tamper detection and runbook | Secure | CloudTrail, EventBridge, SNS; detection and response |
| 12 | Evidence pack | Secure; Cost-Optimized | S3 versioning and access control; storage cost |
| 13 | Reviewer benchmark | Cost-Optimized | Mostly outside the exam: measuring what a control is worth |
| 14 | Codex Security gated scan | Cost-Optimized | Mostly outside the exam: capping the cost of an optional control |
| 15 | S3 and SQS triggers | Resilient; High-Performing; Secure | Decoupling with SQS, dead-letter queues, partial batch failures, idempotency; batching and concurrency; bucket and queue policies |
| 16 | HTTP trigger | Secure; High-Performing; Resilient | API Gateway authentication and authorisation, throttling |
| Stretch | Two accounts, automatic fixing, a third reviewer, a second runtime | Secure | Multi-account structure with AWS Organizations (the two-account lab) |
