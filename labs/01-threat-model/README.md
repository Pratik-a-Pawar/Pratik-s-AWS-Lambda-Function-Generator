# Lab 01: Threat model the generator

## Goal

Before any of the pipeline is built, write a threat model for it: a data flow diagram, the assets, the trust boundaries, at least 15 STRIDE threats with mitigations, and your five top risks. The result is `docs/threat-model.md`, and later labs are judged against it.

## Why this matters

Every control in the design exists because something goes wrong without it. If you build the controls first and reason about threats afterwards, you end up defending what you happened to build rather than what an attacker would target, and the gaps are exactly the places nobody looked.

A threat model forces the questions in the right order. What is worth stealing or changing? Where does data cross from something you control into something you do not? At each crossing, what could an attacker pretend to be, change, deny, read, break or gain? Only then: which control answers that, and does it exist yet?

This project has an unusual boundary. Two of its components are language models that read files an attacker can write, on a public repository, inside CI. That is not a theoretical concern: published research has shown AI agents in GitHub Actions being steered by text in issues and pull requests. A threat model that treats the reviewers as trusted tools would miss the most interesting attack surface in the system.

Finally, a written threat model is something you can defend in an interview: each row is a decision you made and can explain.

## Before you start

- Lab 00 is complete (`lfg labcheck 00` passes).
- You have read section 5 of the design: `docs/superpowers/specs/2026-11-16-lambda-function-generator-design.md`. Sections 5.5 (hardening the AI reviewers) and 10 (unverified items) matter most here.
- You have skimmed `standards/rules.yaml` so you know which rule IDs exist. Only the checker (`lfg validate-spec` and `lfg policy-check`) is built so far.
- The reference threat model lives on the `reference-solutions` branch. Do not read it until you have written yours and run the check.

## Research questions

Answer these from primary sources (the original STRIDE material from Microsoft, the OWASP threat modelling material, GitHub's documentation on workflow triggers and security hardening, and the PromptPwnd research write-up). Write your answers down; the debrief builds on them.

1. What security property does each STRIDE category violate? Which category is about proving who did something, rather than stopping them?
2. What is a trust boundary, and how do you decide where one sits? Is the boundary between two GitHub Actions jobs in the same workflow a trust boundary?
3. What did the PromptPwnd research show about AI agents running in GitHub Actions? Which inputs did the attacks use to reach the model, and what did the agent need to have for the attack to do damage?
4. What is the difference between the `pull_request` and `pull_request_target` triggers? Which code does each check out by default, which secrets and token permissions does each receive, and why is `pull_request_target` combined with a checkout of the PR head considered dangerous?
5. Does GitHub give secrets to a workflow run triggered by a pull request from a fork? Does the answer change for `pull_request_target`?
6. What is the difference between direct and indirect prompt injection? Which one applies to a reviewer that reads source files?
7. What does a STRIDE threat model not find? Name one class of problem it tends to miss.

## Tasks

1. Start from the skeleton. On the learner branch `docs/threat-model.md` already has the six headings and an empty threats table. Keep the headings exactly as they are; the check looks for them.

2. Write **System overview**: in your own words, what the system does, its main components and where each runs. Five or six short paragraphs or a numbered list is enough.

3. Draw the **Data flow diagram** as text inside a fenced code block. Show:
   - every component in section 5 of the design (local Claude Code and hook, the repository, each `pr-checks.yml` job, `deploy.yml`, the two LLM providers, the AWS resources from the bootstrap, a generated function at runtime);
   - the data flows between them, numbered, so threats can refer to them;
   - the trust boundaries, drawn as lines.

4. List the **Assets**: what an attacker would want to steal, change or abuse. At least the two API keys, the deploy roles, the signing profile, the evidence bucket and the generated code. For each, say why it is valuable and where it lives.

5. Describe the **Trust boundaries**: at least the developer machine, the GitHub-hosted runner, the LLM providers and AWS. For each, say what crosses it and what is trusted on each side.

6. Write the **Threats** table, at least 15 rows, columns `ID | Component | STRIDE | Threat | Mitigation | Status`:
   - walk each numbered flow that crosses a boundary and ask all six STRIDE questions;
   - write STRIDE categories in full (`Information disclosure`, not `I`); together the rows must cover all six;
   - at least one threat is prompt injection against a reviewer;
   - a mitigation points at a design section (for example `§5.5 item 3`) or a real rule ID from `standards/rules.yaml`. Never cite a rule that does not exist;
   - `Status` is honest: `Built` (with the rule ID or file), `Designed` (with the design section), or `Open` when nothing covers it yet. A designed control is not built.

7. Write **Top risks**: your five most serious threats, ranked, each with one or two sentences on why it ranks there and what reduces it.

8. Run the check and fix what it reports.

```bash
lfg labcheck 01
```

9. Only now, compare with the reference on the `reference-solutions` branch. Note threats you missed and threats you found that it did not. Add what you missed to your own model in your own words.

```bash
git fetch origin reference-solutions
```

```bash
git show origin/reference-solutions:docs/threat-model.md
```

10. Commit your threat model.

```bash
git add docs/threat-model.md
```

```bash
git commit -m "Add threat model for the generator"
```

## Hints

<details><summary>Hint 1: where to start the table</summary>

Take one boundary crossing at a time, not one component at a time. For flow "PR files go to the Claude reviewer", ask: could the input pretend to be something else? Could it change the output? Could anyone deny doing it? What leaks? What stops it working? What could it gain?

</details>

<details><summary>Hint 2: the categories people forget</summary>

Repudiation is the one most often left empty. Think about who approved a prod deploy, who waived a finding, who changed a function in the console, and what record would prove it. Denial of service in this project is not only about traffic: think about a budget of $10.

</details>

<details><summary>Hint 3: where prompt injection enters</summary>

The reviewers never see the PR title or body (§5.5 item 2), so where else can attacker text sit? Look at every kind of file under `functions/<name>/`, including the ones that are not code. Then ask what a fooled reviewer could do, given what its job is allowed to hold.

</details>

<details><summary>Hint 4: elevation of privilege paths</summary>

Follow the permissions, not the code. Which roles can create other roles? What stops a generated template from attaching a role the checker never sees? Compare your answers with the `LFG-IAM-*` and `LFG-TPL-*` rules and with the deploy role description in §5.6.

</details>

<details><summary>Hint 5: being honest in the Status column</summary>

Ask "could I demonstrate this control today?" If the answer is a test in `tests/lfg/`, it is built. If the answer is a paragraph in the design, it is designed. If the answer is "nothing", it is open, and that row is one of the most useful in the document.

</details>

## Acceptance

```bash
lfg labcheck 01
```

Passing means all seven checks pass: the six headings exist, the data flow diagram is a fenced code block, the threats table has at least 15 complete rows with the six columns, the rows cover all six STRIDE categories, one threat mentions prompt injection and no cell says `TODO`.

The check only confirms the document is complete. Whether the threats are the right ones is what the debrief and the comparison in task 9 are for.

## Debrief

1. Which threat in your model would you fix first if you could build only one control, and why that one?
2. Which of your mitigations depend on an LLM behaving well? For each, what is the deterministic control behind it, if any?
3. Which rows did you mark `Open`, and which later lab should close each one?
4. What did the reference model contain that yours did not? Was it a gap in your method or a disagreement?
5. Where did you draw a trust boundary that you were unsure about, and what decided it?

## Interview questions

1. Walk me through how you would threat model a CI/CD pipeline that deploys to AWS. Where do you start?
2. A GitHub Actions workflow needs AWS access. How do you avoid long-lived keys, and what in the trust policy stops another repository from using the same role?
3. Your pipeline uses an LLM to review code. How would an attacker attack that, and how do you design so that a fooled model cannot cause a bad deploy?

## Maps to

- AWS Solutions Architect Associate: Design Secure Architectures (secure access to AWS resources, workload and application security controls).
- OWASP Top 10 for LLM Applications: LLM01 Prompt Injection.
- OWASP Top 10 CI/CD Security Risks: CICD-SEC-4 Poisoned Pipeline Execution; CICD-SEC-3 Dependency Chain Abuse; CICD-SEC-9 Improper Artifact Integrity Validation.
- MITRE ATT&CK: T1195.002 Compromise Software Supply Chain; T1078.004 Valid Accounts: Cloud Accounts; T1562.008 Impair Defenses: Disable or Modify Cloud Logs.

## Boss challenge

The design rejected automatic fixing inside GitHub Actions and left it as a stretch lab (§4.3). Threat model that option: an AI agent in CI that reads the findings, edits the code and pushes a commit. Add its components and flows to a copy of your diagram, write the new threats it introduces, and decide which existing controls it breaks. End with a short recommendation: the minimum set of controls under which you would accept it, or why you would not.
