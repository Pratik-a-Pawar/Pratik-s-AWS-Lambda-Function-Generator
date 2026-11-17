# Lab 02: Function spec and policy checker

## Goal

Write the checker that decides whether a Lambda function may be deployed: the JSON Schema for `function.spec.yaml`, the loader and validator behind `lfg validate-spec`, and the policy engine and rule modules behind `lfg policy-check`, so that every check in `lfg labcheck 02` passes.

## Why this matters

The generator in Lab 06 can be told to follow the standard, but a prompt is a request, not a control: a model can ignore it, and an attacker can try to talk it out of it. `lfg policy-check` is the part that does not negotiate. It is designed to run after generation and again in CI, and it says no the same way every time.

A checker like this fails in two ways. It can crash on input it did not expect, and a check that crashes tends to get switched off. Worse, it can quietly pass input it did not expect: a list where it assumed a mapping, a `?` where it looked for `*`, a SAM property nobody thought to forbid. Each of those is a way past every rule behind it, and no demo will show it.

This checker was built by an AI coach first, and reviews found exactly those gaps, several rounds in a row. The rules now say "only these shapes are allowed", not "these shapes are forbidden". You will rebuild it, try to break it yourself, and be able to explain each decision in an interview.

## Before you start

- Labs 00 and 01 are complete (`lfg labcheck 00` and `lfg labcheck 01` pass).
- Your virtual environment is active (`source .venv/bin/activate`) and you are at the repository root.
- Read `standards/secure-lambda-standard.md` in full before writing any code. It is the specification in prose: every rule, why it exists, and what it does not cover.
- Read sections 5.1 and 5.2 of the design (`docs/superpowers/specs/2026-11-16-lambda-function-generator-design.md`) and skim `standards/rules.yaml`.
- Treat the tests as the exact specification. Each row of each policy test table names a mutation of the good fixture (`tests/lfg/fixtures/good/`) and the exact set of blocking rule IDs it must produce, no more and no fewer. Each row of the spec test table names a mutation and the path at which an error must be reported. When the standard and a test seem to disagree, the test decides what passes; tell the coach about the disagreement.
- Know which files are yours. You write seven files, which start as skeletons: `schemas/function-spec.schema.json`, `tools/lfg/spec.py` and the five files in `tools/lfg/policy/`. Each skeleton's docstrings state the contract: inputs, outputs, rule IDs and location strings. Everything else is already written and you should not need to change it: `tools/lfg/cli.py`, `cfn_yaml.py`, `yaml_util.py`, `rules.py`, `labcheck.py`, the catalogue and the tests. Do not edit anything under `tests/` or `standards/` until the boss challenge.
- Run the lab check once now so you have a baseline. Almost everything fails with `NotImplementedError`; that is expected.

```bash
lfg labcheck 02
```

Effort, honestly estimated: part A 3 to 4 hours, part B 5 to 7, part C 5 to 8, part D 4 to 6. Plan for 17 to 25 hours in total, spread over two or three weeks. Part C is the hardest. Do the parts in order: every policy test loads the good spec with your `load_spec`, and the IAM and configuration rules reuse two helpers from part B.

## Research questions

Answer from primary sources: the AWS IAM User Guide (its policy evaluation logic and policy grammar pages), the IAM section of the Service Authorization Reference, the AWS SAM Developer Guide and its resource specification, the AWS CloudFormation User Guide, the Python standard library documentation for `re`, `fnmatch` and `datetime`, the PyYAML and jsonschema documentation, and the YAML specification. Write your answers down; the debrief builds on them.

**The design**

1. Why is the spec, and not the template, the source of truth? What could go wrong if the checker trusted the template and checked the spec against it instead?
2. What does "fail closed" mean? Name three places in this checker where an input of an unexpected type could make it fail open, and say what the checker must do instead at each.
3. When the input language is open-ended (SAM properties, intrinsic functions, ways of writing an ARN), why is a deny-list of dangerous inputs weaker than an allow-list of safe ones? What does an allow-list cost you in return?
4. Why do risk acceptances expire, and why can a rule of class `deny` or `require` never be accepted?

**IAM**

5. How does IAM evaluate a permissions boundary together with an identity-based policy? If the boundary allows `s3:GetObject` and the role's policy allows `s3:*`, what can the role do? What if the role's policy allows only `sns:Publish`? Does a boundary limit what a resource-based policy grants?
6. What does `?` mean in an IAM action? Where else in a policy are wildcards interpreted, and are actions compared with or without regard to case?
7. What is a SAM policy template, what does one turn into when SAM processes the template, and why does this checker refuse them even though AWS publishes them?
8. The standard says a `ScheduleV2` event can create an IAM role of its own. Confirm that in the AWS SAM documentation and find which of the event's properties control that role. Why does the checker demand the boundary there too?
9. Why is a deploy role that can create IAM roles dangerous? Which IAM condition key lets you require that every role it creates carries a given permissions boundary, and which actions should that condition be attached to?
10. What does SAM add to the function's role when you give it a `DeadLetterQueue` or an `OnFailure` destination? Why does that make a destination outside the template a risk, even though it never appears under `Policies`?

**Parsing**

11. What does the YAML specification say about a mapping that repeats a key? What does PyYAML's `safe_load` do with one? How could a repeated key let a file show one value to a reviewer and another to a checker?
12. Why is `$` in a Python regular expression not the same as "end of string"? Which `re` function or anchor tests the whole string? The jsonschema package runs a schema's `pattern` with Python's `re`: what does that mean for patterns that end in `$`?
13. What can a CloudFormation macro do to a template after this checker has read it? Where does a macro run, and whose code is it?
14. Which values can PyYAML turn into a `datetime.date` or `datetime.datetime`, and what does `datetime.date.fromisoformat` accept in Python 3.12 besides `YYYY-MM-DD`?

## Tasks

Run a single test while you work with `-k`, for example `pytest tests/lfg/test_spec.py -k name_uppercase`. Commit at the end of each part.

### Part A: the spec schema and loader

1. Write `schemas/function-spec.schema.json` as a JSON Schema draft 2020-12 document from the field table below. No key outside the table may appear at the top level, and no key outside the shapes described may appear in a trigger, a permission, a secret or a risk acceptance.

| Field | Required | Allowed values |
|---|---|---|
| `spec_version` | yes | the integer `1` |
| `name` | yes | a lower-case letter, then 2 to 39 lower-case letters, digits or hyphens |
| `purpose` | yes | a string of 10 to 500 characters |
| `owner` | yes | a non-empty string |
| `runtime` | yes | `python3.13` or `python3.14` |
| `architecture` | yes | `arm64` or `x86_64` |
| `trigger` | yes | exactly one of the five trigger shapes below |
| `permissions` | yes | a list of mappings, each with exactly `actions` (a non-empty list of `<service>:<name>` strings, the service being letters, digits and hyphens and the name letters, digits and `*`), `resources` (a non-empty list of strings) and `reason` (a string of at least 10 characters) |
| `environment` | no | a mapping from names (an upper-case letter, then upper-case letters, digits and underscores) to string values |
| `secrets` | no | a list of mappings, each with exactly `name` (the same naming rule), `source` (`ssm` or `secretsmanager`) and `reference` (a string) |
| `timeout` | yes | an integer from 1 to 900 |
| `memory` | yes | an integer from 128 to 10240 |
| `reserved_concurrency` | no | an integer of 0 or more |
| `failure_destination` | yes | `sqs`, `sns` or `none` |
| `log_retention_days` | yes | one of 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 3653 |
| `data_classification` | yes | `public`, `internal`, `confidential` or `restricted` |
| `risk_acceptances` | no | a list of mappings, each with exactly `rule_id` (`LFG-`, upper-case letters, `-`, three digits), `justification` (at least 20 characters), `accepted_by` (a non-empty string) and `expires` (a string written `YYYY-MM-DD`) |

The five trigger shapes, each a mapping with no other keys:

| `type` | Required keys | Optional keys |
|---|---|---|
| `schedule` | `expression` (string) | `timezone` (string) |
| `eventbridge` | `pattern` (a mapping with at least one key) | |
| `s3` | `bucket` (string), `events` (a non-empty list of strings) | `prefix`, `suffix` (strings) |
| `sqs` | `queue_name` (string) | `batch_size` (integer, 1 to 10000) |
| `http` | `method` (`GET`, `POST`, `PUT`, `PATCH` or `DELETE`), `path` (a string starting with `/`), `auth` (`iam`, `jwt` or `none`) | |

The schema accepts all five trigger types, because later plans enable them. Refusing the three that are not enabled yet is the policy checker's job (LFG-TRG-001), not the schema's.

2. Check the retention list against the CloudWatch Logs API reference for setting a retention policy. If AWS accepts values the table leaves out, write down whether the spec should allow them, and tell the coach.

3. Implement `load_spec` and `validate_spec` in `tools/lfg/spec.py` to the contract in their docstrings.

4. Probe your schema by hand: copy the good fixture, set `name` to a valid name followed by a newline (in YAML, a double-quoted string ending in `\n`), and run `lfg validate-spec` on the copy. Explain the result using your answer to research question 12, and write down what you would change. No test checks this; it is a finding to discuss with the coach.

```bash
cp -r tests/lfg/fixtures/good /tmp/lab02-name
```

```bash
lfg validate-spec /tmp/lab02-name
```

5. Run part A's checks and commit.

```bash
pytest tests/lfg/test_spec.py tests/lfg/test_cli_validate_spec.py
```

```bash
git add schemas/function-spec.schema.json tools/lfg/spec.py
```

```bash
git commit -m "Lab 02 part A: spec schema, loader and validator"
```

### Part B: the engine, risk acceptances and template rules

1. Read the module docstring of `tools/lfg/policy/__init__.py`. The engine registers its rule modules in three tuples (`TEMPLATE_MODULES`, `FUNCTION_MODULES`, `SOURCE_MODULES`) and runs whatever they hold. Before writing code, explain to yourself why there are three tuples and not one list.

2. Implement `get_function` and `is_resource_reference` in `template_rules.py` first: parts C and D reuse them.

3. Implement `check` and `blocking`, and leave `check_template` returning an empty list for now. `test_good_fixtures_are_clean` should pass once the other rule modules also return empty lists; give them a temporary `return []` and remove it when you write them.

4. Implement `acceptance.apply` and run `tests/lfg/test_policy_engine.py`.

5. Before reading LFG-TPL-003 closely, write down every SAM function property you think is dangerous. Then read the list of properties on the `AWS::Serverless::Function` reference page of the AWS SAM Developer Guide and count the ones you had not thought about. Keep the count; the debrief asks for it.

6. Implement `check_template`, one rule at a time, running the matching test rows with `-k`.

7. Fail closed, on purpose: list every value your part B code reads from the spec or the template. For each one, write down what your code does if it is a list, a mapping, a number, `null`, or missing. Any answer that is "crashes" or "passes" is a bug. The test rows on unexpected shapes check some of these, not all.

8. Run part B's checks and commit.

```bash
pytest tests/lfg/test_policy_engine.py tests/lfg/test_policy_template.py
```

```bash
git add tools/lfg/policy
```

```bash
git commit -m "Lab 02 part B: policy engine, risk acceptances and template rules"
```

### Part C: the IAM rules

1. Read LFG-IAM-001 to LFG-IAM-008 and LFG-SPEC-001 in the standard, then the `check_iam` docstring.

2. Before writing any code, attack the rules on paper. In a scratch file outside the repository, write down:
   - five ways to express "every resource" in a `Resource` without typing a bare `*`;
   - five ways to write an action that covers `iam:PassRole` without typing `iam:PassRole`;
   - three ways to give the function a role that the permissions boundary does not constrain.

3. Implement `check_iam`. Do not open `tests/lfg/test_policy_iam.py` yet.

4. Run your attack list against your own checker. Copy the good fixture, edit its `template.yaml`, declare any action you add in its spec too (so that the only violations you see are the ones your attempt should cause), and run the command once per attempt. For each attempt that passes, decide which rule should have caught it and fix your code.

```bash
cp -r tests/lfg/fixtures/good /tmp/lab02-attack
```

```bash
lfg policy-check /tmp/lab02-attack
```

5. Only now run the IAM checks. Read the groups of test rows that start with the comments `R1` to `R7`, `F1` and `F2`: each group is a way past the rules that a review of an earlier version of this checker found. Compare them with your list and note which ones you did not think of.

```bash
pytest tests/lfg/test_policy_iam.py
```

6. Commit.

```bash
git add tools/lfg/policy/iam_rules.py
```

```bash
git commit -m "Lab 02 part C: IAM rules"
```

### Part D: the configuration rules and the command

1. Read LFG-SEC-001, LFG-LOG-001, LFG-REL-001, LFG-NET-001 and LFG-DEP-001 in the standard, then the `check_config` docstring. Note what the standard says each rule cannot see.

2. Implement `check_config`, rule by rule.

3. Read `_policy_check` in `tools/lfg/cli.py`. It is already written and calls your code. Work out, before you run anything, which exit code and output each of these gives: the good fixture; a fixture with `Timeout: 120` in both files; the same with a valid acceptance for LFG-RUN-002; a spec that fails the schema; a missing `src/` directory. Then check your predictions.

```bash
lfg policy-check tests/lfg/fixtures/good
```

```bash
lfg policy-check tests/lfg/fixtures/good --format json
```

4. Run part D's checks, then the whole lab.

```bash
pytest tests/lfg/test_policy_config.py tests/lfg/test_cli_policy_check.py
```

```bash
lfg labcheck 02
```

5. Run the full suite and the linter, then commit.

```bash
pytest -q
```

```bash
ruff check tools tests
```

```bash
git add tools/lfg/policy/config_rules.py
```

```bash
git commit -m "Lab 02 part D: configuration rules"
```

## Hints

<details><summary>Hint 1: where to start each part</summary>

Make the good fixture pass before anything else. A checker that reports a violation on the good fixture fails nearly every row of every table, which hides the one thing you are working on. Then take one test row at a time with `-k`.

</details>

<details><summary>Hint 2: getting every schema error, with its location</summary>

The jsonschema documentation describes a way to get all errors from a validator rather than the first one, and an error object has more than one attribute that describes where it is. Read what `path`, `relative_path` and `absolute_path` each mean, and choose one.

</details>

<details><summary>Hint 3: dates and acceptances</summary>

Look at which Python types PyYAML returns for `2027-01-31` and for `2027-01-31T10:00:00`, and how those two types are related. For expiry, decide first how you will reject a string that `fromisoformat` would accept but that is not written `YYYY-MM-DD`.

</details>

<details><summary>Hint 4: writing a rule that fails closed</summary>

Describe the one good shape exactly ("a mapping whose only keys are A and B, where A is exactly this string") and treat everything that is not that shape as a violation. Checking for each bad shape you can think of is the deny-list mistake in miniature. Exact equality against a known value (`==` on a whole mapping, or a type check plus a value check) is often all a rule needs.

</details>

<details><summary>Hint 5: locations</summary>

Build one base location string per function (`template.yaml:Resources.<id>.Properties`) and extend it as you walk down. Most location bugs come from building the same string in two places.

</details>

<details><summary>Hint 6: wildcards in actions</summary>

The `fnmatch` module has two functions that look the same. Read what the documentation says each one does with upper and lower case, and on which operating systems. For "could this wildcard action match a sensitive action?", compare the literal text before the first wildcard in each pattern.

</details>

<details><summary>Hint 7: the whole string</summary>

Python's `re` module has `search`, `match` and `fullmatch`. Only one of them answers "is the entire string of this form?" without any help from anchors. Try each on `"iam:PassRole\n"`.

</details>

<details><summary>Hint 8: requirements files</summary>

Work in stages: join continuation lines, remove comments, then split each requirement into tokens and classify every token as the pin, an environment marker or an option. A requirement is good only if every token found a place and the pin and hash options are there.

</details>

<details><summary>Hint 9: very deep templates</summary>

Your walk for `Fn::Transform` probably recurses. Find out what Python does about 1,000 levels deep, then read how `cli.py` handles that case. Do not catch that exception inside your rule modules: a rule that swallows it and returns nothing would pass a template it never finished reading.

</details>

## Acceptance

Each part has its own check:

```bash
pytest tests/lfg/test_spec.py tests/lfg/test_cli_validate_spec.py
```

```bash
pytest tests/lfg/test_policy_engine.py tests/lfg/test_policy_template.py
```

```bash
pytest tests/lfg/test_policy_iam.py
```

```bash
pytest tests/lfg/test_policy_config.py tests/lfg/test_cli_policy_check.py
```

The whole lab:

```bash
lfg labcheck 02
```

Passing looks like `418 passed` and an exit code of `0`, with no `failed` and no `error` in the summary (41 for part A, 82 for part B, 146 for part C and 149 for part D). A row that passes by accident is still worth reading; if you cannot explain why it passes, you have found a gap in your understanding or in the tests, and both are worth telling the coach.

## Debrief

1. Which of your attacks from part C did your first version miss, and which rule catches each one now?
2. How many SAM function properties were missing from your list in part B? What does that number say about deny-lists?
3. Where could your checker still fail open? Think about values the tests never try, and about what the standard says the checker cannot see.
4. What did the newline probe in part A show, and how would you fix the schema without breaking it for other JSON Schema implementations?
5. If Plan 6 enables the `sqs` trigger, which of your files change, and which rules need new test rows?

## Interview questions

1. How does a permissions boundary interact with an identity policy, and why would you require one on every role a pipeline creates?
2. How would you stop engineers from deploying a Lambda function with an over-broad IAM role, without a person reviewing every template by hand?
3. Your policy-as-code check passed a template that turned out to be dangerous. How do you find out why, and how do you stop the same class of bypass, not only that one instance?

## Maps to

- AWS Solutions Architect Associate: Design Secure Architectures (least-privilege IAM, permissions boundaries, secrets management, controlled public endpoints); Design Resilient Architectures (failure handling for asynchronous invocations); Design Cost-Optimized Architectures (log retention, timeouts).
- OWASP Serverless Top 10, using the category names the standard uses: over-privileged function permissions and roles; insecure application secrets storage; insecure third-party dependencies; inadequate function monitoring and logging; broken authentication.
- OWASP Top 10 CI/CD Security Risks: CICD-SEC-3 Dependency Chain Abuse.
- MITRE ATT&CK: T1098.003 Account Manipulation: Additional Cloud Roles (why `iam:Attach*` and `iam:Put*` need an acceptance); T1562.008 Impair Defenses: Disable or Modify Cloud Logs (`cloudtrail:StopLogging`); T1552 Unsecured Credentials (secrets in environment variables); T1195.001 Supply Chain Compromise: Compromise Software Dependencies and Development Tools (unpinned dependencies).

## Boss challenge

Add a rule, end to end, that refuses `ReservedConcurrentExecutions: 0` on the function unless a risk acceptance covers it.

First research it: what does a reserved concurrency of 0 do to a function, according to the Lambda Developer Guide? Why could that be a security problem for a scheduled audit function, and why might an incident responder set it on purpose?

Then do it the way the existing rules were done:

1. Choose a new rule ID in the area that fits best, and say why. IDs are never reused or renumbered.
2. Add the rule to `standards/rules.yaml` with class `accept`, a severity, and a CWE if one genuinely applies.
3. Add its `### <ID>` section to `standards/secure-lambda-standard.md`, in the same form as the others: the rule, why it matters, a compliant and a non-compliant example. `tests/lfg/test_rules.py` checks that the standard and the catalogue list the same rules.
4. Update `tests/lfg/test_rules.py`: it pins the exact set of rule IDs and the rule count, so adding a rule properly means changing both, deliberately.
5. Write the failing test rows first: `0` blocks; `0` with an acceptance is accepted; `1` and an absent property are clean. Decide, and test, what happens for `"0"`, `false`, `null` and a `Ref`. In Python, what is `False == 0`, and does it matter here?
6. Implement the rule in the module where it belongs, and say which of the engine's three tuples runs it and why.
7. `pytest -q`, `ruff check tools tests` and `lfg labcheck 02` all pass.

Optional extension: should the spec's `reserved_concurrency` also have to match the template, like `timeout` does under LFG-SPEC-002? Argue for one answer.
