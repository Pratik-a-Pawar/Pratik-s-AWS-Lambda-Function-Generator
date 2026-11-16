# Lab 00: Workstation and account guardrails

## Goal

Set up a Linux workstation inside WSL2 with every tool the project uses, sign in to AWS with a non-root identity in `eu-west-1`, put spending guardrails on AWS and both LLM providers, and answer six research questions that the design could not verify.

## Why this matters

Every later lab assumes three things: the commands behave the same on your machine as in CI, the identity you use cannot do more damage than its job needs, and a mistake costs a few cents rather than your credit.

Bash on Linux is what GitHub-hosted runners and the AWS tools expect, so WSL2 removes a whole class of "works on my machine" problems. Working inside the Linux filesystem, not under `/mnt/c`, keeps file permissions and performance predictable.

The root user of an AWS account cannot be limited by IAM policies. If you use it every day, every phishing page, leaked shell history or compromised tool you run holds the whole account. A non-root identity with short-lived credentials limits what any one mistake can reach.

Cloud and API bills do not stop on their own. A budget alarm will not prevent spending, but it tells you before a misconfigured schedule or a leaked key runs for a month.

Finally, the design marks some facts as unverified. A security project that builds on facts nobody checked is building on sand, so you check them here, from the primary documents.

## Before you start

- A Windows laptop where you can run PowerShell as administrator, with hardware virtualisation enabled.
- An AWS account you control, with access to the root user's sign-in (you will add MFA to it and then stop using it).
- A GitHub account with access to this repository.
- A Claude Pro subscription, an Anthropic Console account and an OpenAI API account (each with the credit described in section 3 of the design).
- About four hours. Installers and sign-ups take longer than expected.

## Research questions

Answer these in `labs/00-workstation/answers.md`, under the headings `## Q1` to `## Q6`. Answer each from the primary documentation (AWS documentation, the AWS Service Authorization Reference, GitHub's documentation, the vendor's own README) and give the URL you used and the date you read it. Where the answer depends on your own account, say what you ran and what it returned.

1. Which Python runtimes does Lambda currently support, and what are their deprecation dates? Should this project move its default from `python3.13` to `python3.14`?
2. What is the exact `sub` claim GitHub sends to AWS for a workflow job that targets an environment named `prod`?
3. Why is your everyday AWS identity not the root user, and what can only root do?
4. What does Lambda's free tier cover each month, and which resource in this project is most likely to cost money first?
5. For each entry in `wildcard_only_actions` in `standards/rules.yaml`, does the Service Authorization Reference confirm the action cannot be scoped to a resource?
6. Can your OpenAI API account run `npx @openai/codex-security scan --dry-run` on this repository, and what does the dry run report?

These are for your own notes, not for `answers.md`:

- Why is working under `/mnt/c` from WSL2 slower and less predictable than working in the Linux home directory?
- What is the difference between an organisation instance and an account instance of IAM Identity Center, and which one lets you sign in to an AWS account with `aws configure sso`? What does enabling the organisation instance do to a standalone account?
- Does an AWS Budgets alert stop spending? Is the spend limit in the Anthropic Console a hard stop? Is a project budget in the OpenAI dashboard a hard stop or a notification?

## Tasks

The first two commands run in PowerShell as administrator on Windows. Every command after that runs in bash inside Ubuntu.

1. Install WSL2 with Ubuntu 24.04. List the available distributions first and use the exact name the list shows.

```powershell
wsl --list --online
```

```powershell
wsl --install -d Ubuntu-24.04
```

Restart if asked, open Ubuntu, create your Linux user, then confirm the release:

```bash
cat /etc/os-release
```

2. Make a working directory in the Linux filesystem. Keep all project work under it, never under `/mnt/c`.

```bash
mkdir -p ~/src
```

3. Update Ubuntu and install Git and Python. Ubuntu 24.04's `python3` must report 3.12 or later.

```bash
sudo apt update
```

```bash
sudo apt upgrade -y
```

```bash
sudo apt install -y git python3 python3-venv python3-pip unzip
```

```bash
python3 --version
```

Set your Git name and email with `git config --global` before your first commit.

4. Install AWS CLI v2 by following the Linux instructions in the AWS Command Line Interface User Guide. Pick the installer that matches `uname -m`, and verify the download's signature as the guide describes. Then:

```bash
aws --version
```

The output must start with `aws-cli/2`.

5. Install the AWS SAM CLI by following the Linux instructions in the AWS SAM Developer Guide.

```bash
sam --version
```

6. Install Terraform from HashiCorp's own instructions for Ubuntu.

```bash
terraform version
```

7. Install Docker Desktop on Windows and turn on WSL integration for your Ubuntu distribution in its settings. SAM uses Docker for container builds and local invocation. From Ubuntu:

```bash
docker run --rm hello-world
```

8. Install the GitHub CLI from its official Linux instructions and sign in.

```bash
gh auth login
```

```bash
gh auth status
```

9. Install Claude Code by following Anthropic's Claude Code documentation for Linux, and sign in with your Claude Pro account.

```bash
claude --version
```

10. Clone the repository into `~/src`, create the virtual environment and install the project. Replace `<owner>/<repo>` with the repository's GitHub name.

```bash
cd ~/src
```

```bash
gh repo clone <owner>/<repo>
```

```bash
cd <repo>
```

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
lfg --version
```

Activate the virtual environment (`source .venv/bin/activate`) in every new shell before running `lfg`.

11. Lock down the root user: in the AWS console, signed in as root, turn on MFA for root and check that root has no access keys. Activate IAM access to the Billing and Cost Management console while you are there; task 13 needs it.

12. Create a non-root identity with administrator access for yourself and a CLI profile for it in `eu-west-1`. IAM Identity Center with `aws configure sso` is the preferred route. If you choose another route, it must give the CLI short-lived credentials and must not be root. Then sign out of root.

```bash
aws configure sso
```

```bash
export AWS_PROFILE=<your profile name>
```

```bash
aws sts get-caller-identity
```

```bash
aws configure get region
```

The ARN must not end in `:root`, and the region must be `eu-west-1`.

13. Signed in as your non-root identity, create a monthly cost budget in AWS Budgets with an email alert on actual spend and one on forecast spend. Choose a small amount; this account should cost almost nothing. Confirm it from the CLI:

```bash
aws budgets describe-budgets --account-id "$(aws sts get-caller-identity --query Account --output text)"
```

14. Set a monthly spend limit in the Anthropic Console and a project budget in the OpenAI dashboard, matching the credit you have. Write down whether each is a hard stop or an alert (research question above). Keep API keys in a password manager: never in the repository, a committed file or your shell history.

15. Answer Q1 to Q6 in `labs/00-workstation/answers.md`. Replace every `TODO`.

16. Run the acceptance check (below), then commit your answers.

```bash
git add labs/00-workstation/answers.md
```

```bash
git commit -m "Answer Lab 00 research questions"
```

## Hints

<details><summary>Hint 1: WSL2 will not install</summary>

Check that virtualisation is enabled in the laptop's firmware settings and that Windows is up to date. `wsl --status` tells you which WSL version is the default. Microsoft's WSL documentation has a troubleshooting page for the common error codes.

</details>

<details><summary>Hint 2: a tool is installed but the check cannot find it</summary>

The check uses your `PATH` inside WSL, as seen by the shell that runs `lfg`. Open a new shell after installing, and run `command -v <tool>`. Windows programs on the Windows `PATH` do not count; `docker` comes from Docker Desktop's WSL integration, not from a separate install inside Ubuntu.

</details>

<details><summary>Hint 3: choosing how to sign in to AWS</summary>

Read the IAM Identity Center documentation on instance types before you enable it. The question that decides it is which instance type can grant access to an AWS account through permission sets. Whatever you choose, run `aws sts get-caller-identity` and read the ARN: it tells you which kind of principal you are.

</details>

<details><summary>Hint 4: the budget check fails with AccessDenied</summary>

Two separate things must allow it: the account must have IAM access to billing activated (a root-only task; see Q3), and your identity's permissions must include viewing budgets. Read the error message for which one it is.

</details>

<details><summary>Hint 5: answering Q2 and Q5 well</summary>

For Q2, GitHub's OpenID Connect documentation has a section with example subject claims, and its REST API documentation describes how a repository's subject claim can be customised. You need both. For Q5, in each service's "Actions defined by" table in the Service Authorization Reference, look at the "Resource types" column for each action, and read the reference's introduction on what an empty value means.

</details>

## Acceptance

With your AWS profile exported, from the repository root:

```bash
lfg labcheck 00
```

Passing looks like `12 passed`: one check per tool (`git`, `python3`, `aws`, `sam`, `terraform`, `docker`, `gh`, `claude`), the Python version, your answers, and two AWS checks (your identity is not root; the account has at least one budget). If the summary says `skipped`, the AWS checks did not run: export `AWS_PROFILE` and run it again.

## Debrief

1. What would an attacker be able to do with your everyday AWS credentials today? What stops them doing more?
2. Your budget alarm fires at 2 a.m. What do you check first, and in which service?
3. Which of your six answers turned out different from what the design assumed, and what in the project should change as a result?
4. Which answers could you not confirm from a primary source, and how will you confirm them later?

## Interview questions

1. Why should nobody use the AWS root user day to day, and what controls would you put on it in a new account?
2. How would you give engineers CLI access to AWS without long-lived access keys?
3. A developer's laptop was compromised. Which of their credentials do you rotate first, and how do you find out what was used?

## Maps to

- AWS Solutions Architect Associate: Design Secure Architectures (secure access to AWS resources: root user protection, IAM Identity Center, MFA); Design Cost-Optimized Architectures (AWS Budgets, free tier awareness).
- MITRE ATT&CK: T1078.004 Valid Accounts: Cloud Accounts; T1496 Resource Hijacking (why a budget alarm is also a detection control).

## Boss challenge

Make root use visible. Build an alert, by hand in the console or with the CLI, that emails you whenever the root user signs in to the console. Find out from the CloudTrail documentation which Region console sign-in events are recorded in and what that means for where your rule must live. Then sign in as root once, confirm the alert arrives, and write down how long it took and what the event told you about the sign-in.
