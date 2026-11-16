# Lab 00 answers

These are the reference answers, written by the AI coach. The coach's build environment could not reach AWS, GitHub or OpenAI documentation and has no AWS account, so nothing below was checked against a primary source during the build. Each answer gives what is well established, then what you must confirm yourself and in which document. Where a specific figure or date was not certain, it is left out rather than guessed. Your own answers replace these on the learner branch, with the URL you used and the date you read it.

## Q1 Lambda Python runtimes and the default

**Well established.** Lambda offers managed Python runtimes named `python3.N`. The "Lambda runtimes" page of the AWS Lambda Developer Guide lists each supported runtime with three dates: when it is deprecated, when you can no longer create functions on it, and when you can no longer update them. Lambda's runtime policy ties deprecation to the language version reaching the end of its upstream support, and each Python feature release gets about five years of upstream support (see the "Status of Python versions" page in the Python Developer's Guide). A newer runtime therefore normally gives a later deprecation date and fewer forced upgrades.

**Not confirmed.** Which Python runtimes the page lists today, their exact dates, and whether `python3.14` is available in `eu-west-1`. The design records a search snippet saying `python3.14` is supported until June 2029 (design §5.1, §10 item 1). Treat that with suspicion: Python 3.14 was released in October 2025, so upstream support runs to about 2030, and a Lambda deprecation date a year earlier would be unusual. Read the dates from the runtimes page itself.

**Should the default move?** Both runtimes are already allowed by the spec schema and by LFG-RUN-001, so this is a generator decision (design §5.1), not a checker change. Move the default to `python3.14` only when all of these hold: the runtimes page lists it as supported with a later deprecation date than `python3.13`; SAM CLI has a build image for it on `arm64`; Powertools for AWS Lambda (Python) supports it; and the scanners in the static job handle it. Until then, keep `python3.13`.

## Q2 The OIDC `sub` claim for the `prod` environment

**Well established.** GitHub's OpenID Connect documentation describes the default subject claim. For a job that references an environment, it takes the form `repo:<owner>/<repo>:environment:<environment name>`, so for this project `repo:<owner>/<repo>:environment:prod`. The environment form replaces the branch form (`repo:<owner>/<repo>:ref:refs/heads/main`), so a trust policy written for one does not match a job that uses the other. The trust policy should also check the audience claim (`aud`) that the AWS credentials action requests.

**Why only you can answer it.** Three things depend on your repository, not on the documentation:

- the exact owner and repository names, as GitHub puts them in the token;
- whether the repository or its owner has customised the subject claim template, which changes the format entirely (GitHub's REST API documentation describes how to read a repository's OIDC subject customisation; run that with `gh api`);
- the design lists the trust-policy condition format as unverified (§10 item 2), because neither AWS nor GitHub documentation could be opened during the design.

Confirm the format in GitHub's OpenID Connect documentation (the example subject claims) and the AWS IAM User Guide section on creating a role for web identity or OpenID Connect federation. In Lab 04, check the claims of a real token from a `prod` job before the prod role trusts it. Never print the token itself.

## Q3 Why not root, and what only root can do

**Why not root.** The root user has complete access to every resource and to billing, and in a standalone account no IAM policy can restrict it. If its credentials leak, the attacker owns the account and can lock you out of it. Using root daily also means the most powerful credential is the one most exposed: typed into the most pages, held by the most tools. A non-root identity can be limited, given short-lived credentials, and replaced if compromised. Taking over valid cloud accounts is a standard attacker technique (MITRE ATT&CK T1078.004, Valid Accounts: Cloud Accounts).

**What only root can do.** The IAM User Guide has a page, "Tasks that require root user credentials". Tasks on it that are well established include:

- changing account settings such as the account name, the root user's email address and password, and managing root access keys;
- closing the account;
- restoring IAM permissions when the only IAM administrator has removed their own access;
- activating IAM access to the Billing and Cost Management console;
- editing or deleting an S3 bucket policy that denies all principals, including after a misconfiguration;
- configuring MFA delete on an S3 bucket.

AWS has moved tasks off that list over time, so confirm the current list on that page rather than relying on this one.

**Practice.** MFA on root, no root access keys, credentials stored offline, and root used only for the tasks on that list.

## Q4 Lambda free tier and the first cost

**Well established.** Lambda's long-standing free allowance is 1 million requests and 400,000 GB-seconds of compute per month. A scheduled function in this project is far below that: a 256 MB function (0.25 GB) running for 5 seconds once a day uses about 0.25 × 5 × 30 = 37.5 GB-seconds a month.

**Not confirmed.** AWS has revised its Free Tier offers for newer accounts, and which offer applies depends on when your account was created. Check the AWS Free Tier page and your own account's Billing and Cost Management console. The coach could not confirm the current terms.

**What costs money first.** Probably not AWS at all: the Anthropic and OpenAI credit spent by the CI reviewers (design §9). Within AWS, the likely first costs are things with a monthly charge per resource or no free allowance, rather than Lambda itself:

- a Secrets Manager secret, if a function uses one instead of an SSM Parameter Store parameter (charged per secret per month after its trial);
- a KMS customer managed key, if one is added (a monthly charge per key);
- GuardDuty after its 30-day trial, if the optional responder is used (design §5.10);
- CloudTrail beyond the first copy of management events, such as data events or a second trail;
- CloudWatch Logs, if a function logs heavily (LFG-LOG-001 makes retention mandatory, which limits storage, not ingestion);
- S3 storage for the artefact, evidence and state buckets, which the design estimates at cents (§9).

Confirm each on its service's pricing page; this list has no prices on purpose.

## Q5 The `wildcard_only_actions` list

**How to check.** In the Service Authorization Reference, each service has an "Actions defined by" table. If an action's "Resource types" column is empty, the action cannot be scoped to a resource and the policy must use `Resource: "*"`. If it lists a resource type, the action can be scoped and does not belong on this list.

**What the coach expects, not confirmed:**

- `ec2:Describe*`: EC2 Describe actions are widely granted on `"*"` because most do not support resource-level permissions. But this entry is a wildcard covering many actions, so confirming it means checking every matching action in the EC2 table. If any of them lists a resource type, the entry is too broad and should name individual actions instead.
- `iam:GenerateCredentialReport` and `iam:GetCredentialReport`: the credential report covers the whole account, so no resource type is expected. Check the IAM table.
- `iam:ListUsers`: the coach is not sure. IAM list actions may accept a resource type (for example users under a path). If the reference lists one, `Resource: "*"` is avoidable and the entry should come off the list.
- `xray:PutTraceSegments` and `xray:PutTelemetryRecords`: no resource type is expected, since these send trace data rather than act on a named resource. Check the X-Ray table.

**Why only your reading can answer it.** The reference could not be opened during the build, and AWS adds resource-level support to actions over time, so the answer has a date. Record, for each entry, what the table says and the date you read it. Any entry that turns out to be scopable is a change to `standards/rules.yaml` and the standard, recorded like the plan's other amendments.

## Q6 Codex Security dry run

**Why only your account can answer it.** The command needs your OpenAI API key and runs against your account's access. The design records that the Codex Security README says some requests need "Trusted Access for Cyber" without saying which (design §4.2, §5.4), and lists whether a pay-as-you-go account can run scans, and what a scan costs, as unverified (§10 item 4). The coach has not run the command and has not confirmed that the package name, the `scan` subcommand or the `--dry-run` flag behave as written.

**Before you run it.** Read the README of the `openai/codex-security` repository on GitHub (design §13) for what `--dry-run` does, and in particular whether it calls the API or spends credit. Set the OpenAI project budget first (task 14). Supply the key through an environment variable in your shell, typed with `read -rs` so it stays out of shell history, never in a file in the repository.

**What to record.** The exit status, what the dry run says it would scan, any cost estimate, and any access error word for word. An access error that mentions Trusted Access answers §10 item 4: Codex Security stays advisory (§5.4) until access is granted.
