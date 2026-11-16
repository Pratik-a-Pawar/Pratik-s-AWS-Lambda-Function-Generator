# Plan 1 of 7: Core Toolkit and Labs 00-02 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `lfg` command-line tool's spec validator and policy checker, the secure Lambda standard they enforce, and the tooling and briefs for Labs 00, 01 and 02, so Pratik can start the lab track.

**Architecture:** A small Python package (`tools/lfg/`) reads a function's `function.spec.yaml` and SAM `template.yaml` and reports violations of a rule catalogue (`standards/rules.yaml`). The complete solution is built on the `reference-solutions` branch. A script then replaces lab-owned files with skeletons to produce the learner branch, and `lfg labcheck` runs each lab's acceptance checks.

**Tech Stack:** Python 3.12+, `jsonschema`, `PyYAML`, `pytest`, `ruff`. No AWS or LLM access is needed for this plan.

**Spec:** `docs/superpowers/specs/2026-11-16-lambda-function-generator-design.md`

## The plan series

The design covers several independent subsystems, so it is built as seven plans. Each one leaves working, tested software and releases the labs that depend on it. Plans 2 to 7 are written when their turn comes.

| Plan | Builds | Labs released |
|---|---|---|
| **1 (this one)** | Spec schema, rule catalogue, policy checker, lab tooling | 00, 01, 02 |
| 2 | Two hand-written reference functions, scanner configuration, PR static-checks workflow | 03, 05 |
| 3 | `/new-lambda` and `/fix-findings` skills, hook, findings schema, Claude and Codex review jobs, publish job, gate | 06, 07, 08 |
| 4 | Terraform bootstrap, deploy workflow, signing, bill of materials, provenance, tamper detection and runbook | 04, 09, 10, 11 |
| 5 | Evidence pack, reviewer benchmark, Codex Security workflow | 12, 13, 14 |
| 6 | S3, SQS and HTTP triggers with their rules | 15, 16 |
| 7 | Architecture and cost documents, stretch-lab briefs, final README pass | Stretch |

Lab numbers follow the learning order in the design; plan numbers follow what can be built and verified first.

## Global Constraints

- Python 3.12 or later. Runtime dependencies are limited to `jsonschema` and `PyYAML`. Development dependencies: `pytest`, `ruff`.
- Rule IDs have the form `LFG-<AREA>-<NNN>`. An ID is never reused or renumbered.
- Exit codes for every `lfg` subcommand: `0` clean, `1` violations found, `2` unusable input or usage error.
- Fail closed: anything the checker cannot parse or does not recognise is a violation or exit `2`, never a pass.
- Allowed runtimes: `python3.13`, `python3.14`. Architectures: `arm64`, `x86_64`.
- Stages are `dev` and `prod`. Deployed resource names start `lfg-<stage>-`. The permissions boundary policy is named `lfg-function-boundary`. Region is `eu-west-1`.
- Enabled trigger types in this plan: `schedule`, `eventbridge`. The schema accepts `s3`, `sqs` and `http`; the policy checker refuses them until Plan 6.
- Prose is International English. No secrets, AWS account IDs or email addresses are committed.
- The full solution is committed on `reference-solutions`. The learner branch `claude/youthful-sagan-mt8uqi` is generated from it by `tools/dev/skeletonise.py`. Push only to those two branches.
- Every commit message ends with the two attribution trailers used in this repository's existing commits.

## Review Focus

Inputs the design implies but does not spell out, most likely to bite first. Each has a test in the task named.

1. **IAM permissions written in a shape the checker does not walk.** SAM accepts managed policy names, policy templates, an external `Role`, a `Statement` that is a mapping instead of a list, and `Action` as a string or a list. A checker that handles one shape silently passes the others. Expected: only inline statement documents are accepted; every other shape is a violation. (Task 4)
2. **Checks bypassed by where a property is set.** `Globals`, a raw `AWS::Lambda::Function`, a standalone `AWS::IAM::Role`, or a second function in the same template all escape per-function checks. Expected: refused outright. (Task 3)
3. **IAM action spelling.** Actions are case-insensitive and may contain wildcards, so `IAM:PassRole` and `iam:Pass*` must not slip past rules written for `iam:PassRole`. Expected: comparison is case-insensitive and any wildcard inside an action name needs a risk acceptance. (Task 4)
4. **Risk acceptances at the edges.** Expired, expiring today, naming an unknown rule, naming a rule that can never be accepted. Expected: valid through the expiry date inclusive; the other three are violations themselves. (Task 3)
5. **Unreadable input.** Missing files, invalid YAML, a YAML document that is a list, a template using short-form intrinsic tags such as `!Sub` and `!GetAtt`. Expected: intrinsic tags load; everything else exits `2` with a one-line message and no traceback. (Tasks 1 and 3)

## Amendments made during the build

The per-task reviews demonstrated ways past several rules as this plan first worded them. Each was ruled on during the build and the code follows the rulings below. Where a task's text further down disagrees with this section, this section and `standards/rules.yaml` are correct.

**Catalogue.** 28 rules, not 26. Two were added:

| ID | Class | Severity | CWE | Summary |
|---|---|---|---|---|
| LFG-TPL-003 | deny | high | CWE-1188 | Only allow-listed function attributes, function properties and event properties may appear |
| LFG-TPL-004 | deny | critical | CWE-829 | Only allow-listed top-level sections may appear, the only transform is `AWS::Serverless-2016-10-31`, and `Parameters` is exactly the `Stage` parameter limited to `dev` and `prod` |

**Loaders (Tasks 1 and 3).**
- Both YAML loaders reject duplicate mapping keys, through a shared loader in `tools/lfg/yaml_util.py`.
- `load_spec` converts YAML dates to ISO strings, so an unquoted `expires` date works.
- Unreadable, undecodable, impossibly dated or too deeply nested files raise the load errors and the commands exit `2`.

**Risk acceptances (Task 3).** An `expires` that is not a real date, a `risk_acceptances` value that is not a list, and an entry that is not a mapping are each `LFG-RA-001`.

**IAM rules (Task 4).**
- `?` is a wildcard wherever `*` is.
- An action must have the form `service:name`. A wildcard in the service part, or an action made only of wildcards, is `LFG-IAM-001`. Any other malformed action string is `LFG-IAM-007`.
- A statement key other than `Sid`, `Effect`, `Action`, `Resource` or `Condition` is `LFG-IAM-007`.
- Resource forms are a closed list: a plain string; a `Ref` or `Fn::GetAtt` to a resource in the same template; or a string-form `Fn::Sub` whose variables are `AWS::Partition`, `AWS::Region`, `AWS::AccountId`, `Stage` or a resource in the template. `Fn::Join`, the `Fn::Sub` list form and every other intrinsic are `LFG-IAM-007`.
- `LFG-IAM-005` fires on any resource whose resource part is entirely wildcards (for example `arn:aws:s3:::*`), not only on the literal `"*"`.
- The permissions boundary must equal exactly `{"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary"}`. This replaces the substring test this plan specified.
- A `RoleArn` on a ScheduleV2 event is `LFG-IAM-004`.

**Configuration rules and the command (Task 5).**
- A dead-letter queue or failure destination must be an SQS queue (`Fn::GetAtt <id>.Arn`) or an SNS topic (`Ref`) declared in the same template, of the type the spec's `failure_destination` names, with no extra keys. `OnSuccess` is refused.
- `Environment` may contain only `Variables`.
- A requirement line may carry only `--hash=sha256:` options with exactly 64 hex characters, one `==` pin without wildcards, and no `@` reference.
- `lfg policy-check` loads every input and checks that `src/` exists before validating; with `--format json` it always prints JSON, including for a schema-invalid spec (`spec_errors`).

**Known limits, stated in the standard.** The checker cannot judge whether a scoped ARN is narrow enough; `LFG-SEC-001` judges variable names, not values; SAM adds send permissions for failure destinations that are not compared with the spec.

---

## File Structure

```
pyproject.toml                         package metadata, console script lfg, pytest and ruff config
tools/lfg/__init__.py                  __version__ = "0.1.0"
tools/lfg/cli.py                       argument parsing and exit codes only           (coach-owned)
tools/lfg/spec.py                      load and schema-validate a function spec       (Lab 02)
tools/lfg/cfn_yaml.py                  load SAM/CloudFormation YAML with intrinsics   (coach-owned)
tools/lfg/rules.py                     load the rule catalogue                        (coach-owned)
tools/lfg/policy/__init__.py           Violation, check(), blocking()                 (Lab 02)
tools/lfg/policy/acceptance.py         risk-acceptance handling                       (Lab 02)
tools/lfg/policy/template_rules.py     template shape, naming, spec/template match    (Lab 02)
tools/lfg/policy/iam_rules.py          IAM rules                                      (Lab 02)
tools/lfg/policy/config_rules.py       secrets, logging, reliability, deps, network   (Lab 02)
tools/lfg/labcheck.py                  run a lab's acceptance checks                  (coach-owned)
tools/dev/skeletonise.py               swap lab-owned files for skeletons             (coach-owned)
schemas/function-spec.schema.json      the spec schema                                (Lab 02)
standards/rules.yaml                   machine-readable rule catalogue
standards/secure-lambda-standard.md    human-readable standard
tests/lfg/                             unit tests; these are also the Lab 02 checks
tests/lfg/fixtures/good/               one complete compliant function directory
tests/dev/test_skeletonise.py
labs/manifest.yaml                     lab number -> title, owned files, checks
labs/checks/                           checks that are not unit tests (Labs 00, 01)
labs/00-workstation/README.md
labs/01-threat-model/README.md
labs/02-spec-and-policy/README.md
labs/02-spec-and-policy/skeleton/      skeleton copy of every Lab 02 file, same relative paths
docs/threat-model.md                   reference threat model (Lab 01 solution)
docs/learning-roadmap.md
README.md
```

---

### Task 1: Project scaffold, spec schema and `lfg validate-spec`

**Files:**
- Create: `pyproject.toml`, `tools/lfg/__init__.py`, `tools/lfg/cli.py`, `tools/lfg/spec.py`, `schemas/function-spec.schema.json`
- Create: `tests/lfg/conftest.py`, `tests/lfg/test_spec.py`, `tests/lfg/test_cli_validate_spec.py`, `tests/lfg/fixtures/good/function.spec.yaml`

**Interfaces:**
- Produces:
  - `lfg.spec.SpecLoadError(Exception)`
  - `lfg.spec.SpecError` frozen dataclass: `path: str`, `message: str`
  - `lfg.spec.load_spec(path: Path) -> dict`, raising `SpecLoadError` if the file is missing, is not valid YAML, or its top level is not a mapping
  - `lfg.spec.validate_spec(spec: dict) -> list[SpecError]`, sorted by `path`; `path` is a dotted location such as `permissions[0].reason`, or `(root)`
  - `lfg.cli.main(argv: list[str] | None = None) -> int`
  - pytest fixtures in `conftest.py`: `good_dir` (a `tmp_path` copy of `tests/lfg/fixtures/good/`), `good_spec` (a fresh dict loaded from it)

- [ ] **Step 1: Create the `reference-solutions` branch**

```bash
git checkout claude/youthful-sagan-mt8uqi
git checkout -b reference-solutions
```

- [ ] **Step 2: Write `pyproject.toml`**

Project name `lfg`, version `0.1.0`, `requires-python = ">=3.12"`, dependencies `jsonschema>=4.23` and `PyYAML>=6.0`, optional dependency group `dev` with `pytest>=8` and `ruff>=0.6`. Packages are found under `tools/` (setuptools `packages.find` with `where = ["tools"]`, `include = ["lfg*"]`). Console script `lfg = "lfg.cli:main"`. Pytest `testpaths = ["tests"]`, and a registered marker `aws: needs AWS credentials`. Ruff line length 100.

Run: `pip install -e ".[dev]"`
Expected: installs without error; `lfg --version` is not yet available.

- [ ] **Step 3: Write the good spec fixture**

`tests/lfg/fixtures/good/function.spec.yaml`:

```yaml
spec_version: 1
name: iam-key-age-audit
purpose: Report IAM access keys older than the allowed age to the security alert topic.
owner: pratik-a-pawar
runtime: python3.13
architecture: arm64
trigger:
  type: schedule
  expression: rate(1 day)
  timezone: UTC
permissions:
  - actions: [iam:GenerateCredentialReport, iam:GetCredentialReport]
    resources: ["*"]
    reason: Credential report actions do not support resource-level permissions.
  - actions: [sns:Publish]
    resources: [AlertTopic]
    reason: Publish the findings summary to the alert topic.
environment:
  MAX_KEY_AGE_DAYS: "90"
secrets: []
timeout: 30
memory: 256
failure_destination: sqs
log_retention_days: 30
data_classification: internal
risk_acceptances: []
```

- [ ] **Step 4: Write the failing schema tests**

`tests/lfg/test_spec.py`. One test that the good spec has no errors, then a parametrised test: deep-copy `good_spec`, apply the mutation, assert at least one `SpecError` whose `path` equals the expected path.

| Test id | Mutation | Expected `path` |
|---|---|---|
| `name_uppercase` | `name = "Bad_Name"` | `name` |
| `name_too_short` | `name = "ab"` | `name` |
| `purpose_too_short` | `purpose = "short"` | `purpose` |
| `runtime_unknown` | `runtime = "python3.9"` | `runtime` |
| `arch_unknown` | `architecture = "arm"` | `architecture` |
| `trigger_type_unknown` | `trigger.type = "kinesis"` | `trigger` |
| `schedule_missing_expression` | delete `trigger.expression` | `trigger` |
| `eventbridge_empty_pattern` | `trigger = {type: eventbridge, pattern: {}}` | `trigger` |
| `action_bad_format` | `permissions[0].actions = ["ListUsers"]` | `permissions[0].actions[0]` |
| `reason_too_short` | `permissions[0].reason = "need it"` | `permissions[0].reason` |
| `timeout_too_high` | `timeout = 901` | `timeout` |
| `memory_too_low` | `memory = 64` | `memory` |
| `retention_not_allowed` | `log_retention_days = 45` | `log_retention_days` |
| `classification_unknown` | `data_classification = "secret"` | `data_classification` |
| `failure_destination_unknown` | `failure_destination = "email"` | `failure_destination` |
| `acceptance_bad_rule_id` | `risk_acceptances = [{rule_id: "IAM-5", ...valid rest}]` | `risk_acceptances[0].rule_id` |
| `acceptance_short_justification` | justification of 5 characters | `risk_acceptances[0].justification` |
| `unknown_top_level_key` | add `backdoor: true` | `(root)` |
| `missing_required` | delete `owner` | `(root)` |
| `secret_bad_source` | `secrets = [{name: DB_PASSWORD_PARAM, source: "env", reference: "/x"}]` | `secrets[0].source` |

Also three positive tests: a valid `eventbridge` trigger (`pattern: {source: ["aws.ec2"]}`), a valid `http` trigger (`method: GET`, `path: /health`, `auth: iam`), and a valid risk acceptance (`rule_id: LFG-RUN-002`, a 20-character justification, `accepted_by: pratik-a-pawar`, `expires: "2027-01-31"`).

And load tests: `load_spec` raises `SpecLoadError` for a missing file, for the content `": :\n- ["`, and for a file containing `- a\n- b\n`.

Run: `pytest tests/lfg/test_spec.py -q`
Expected: collection error, `lfg.spec` not found.

- [ ] **Step 5: Write `schemas/function-spec.schema.json`**

JSON Schema draft 2020-12, `additionalProperties: false` at every object level. Values the tests pin:

- `spec_version`: const `1`
- `name`: pattern `^[a-z][a-z0-9-]{2,39}$`
- `purpose`: string, 10 to 500 characters
- `owner`: string, at least 1 character
- `runtime`: enum `python3.13`, `python3.14`
- `architecture`: enum `arm64`, `x86_64`
- `trigger`: `oneOf` five shapes selected by `type`:
  - `schedule`: `expression` (required, string), `timezone` (string, default `UTC`)
  - `eventbridge`: `pattern` (required, object, `minProperties: 1`)
  - `s3`: `bucket` (required), `events` (required, non-empty array of strings), optional `prefix`, `suffix`
  - `sqs`: `queue_name` (required), `batch_size` (integer 1 to 10000, default 10)
  - `http`: `method` (enum `GET`, `POST`, `PUT`, `PATCH`, `DELETE`), `path` (pattern `^/`), `auth` (enum `iam`, `jwt`, `none`), all required
- `permissions`: array of objects with `actions` (non-empty array, each matching `^[A-Za-z0-9-]+:[A-Za-z0-9*]+$`), `resources` (non-empty array of strings), `reason` (string, at least 10 characters)
- `environment`: object, keys matching `^[A-Z][A-Z0-9_]*$`, string values
- `secrets`: array of objects with `name` (pattern `^[A-Z][A-Z0-9_]*$`), `source` (enum `ssm`, `secretsmanager`), `reference` (string)
- `timeout`: integer 1 to 900
- `memory`: integer 128 to 10240
- `reserved_concurrency`: integer, minimum 0, optional
- `failure_destination`: enum `sqs`, `sns`, `none`
- `log_retention_days`: enum `1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 3653`
- `data_classification`: enum `public`, `internal`, `confidential`, `restricted`
- `risk_acceptances`: array of objects with `rule_id` (pattern `^LFG-[A-Z]+-[0-9]{3}$`), `justification` (at least 20 characters), `accepted_by` (at least 1 character), `expires` (pattern `^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

Required at top level: everything except `reserved_concurrency`, `environment`, `secrets`, `risk_acceptances`.

- [ ] **Step 6: Implement `tools/lfg/spec.py`**

`load_spec` uses `yaml.safe_load`. `validate_spec` uses `jsonschema.Draft202012Validator` against the schema file, located relative to the repository root (`Path(__file__).resolve().parents[2] / "schemas"`). Convert each error's `absolute_path` to the dotted form; an error with an empty path reports `(root)`. An error raised inside a `oneOf` branch of `trigger` reports `trigger`.

Run: `pytest tests/lfg/test_spec.py -q`
Expected: all pass.

- [ ] **Step 7: Write the failing CLI tests**

`tests/lfg/test_cli_validate_spec.py`, calling `lfg.cli.main([...])` and reading output with `capsys`:

- `main(["--version"])` prints `lfg 0.1.0`, returns `0`
- `main(["validate-spec", str(good_dir)])` prints `OK: iam-key-age-audit`, returns `0`
- after rewriting the spec in `good_dir` with `timeout: 901`: output contains the line prefix `timeout: `, returns `1`
- `main(["validate-spec", str(tmp_path / "missing")])` returns `2`, and stderr contains `function.spec.yaml` and does not contain `Traceback`
- `main(["frobnicate"])` returns `2`

- [ ] **Step 8: Implement `tools/lfg/cli.py`**

`argparse` with subparsers. `validate-spec <function_dir>` reads `<function_dir>/function.spec.yaml`. Errors print one per line as `<path>: <message>` on stdout. `SpecLoadError` prints to stderr and returns `2`. `main` catches `SystemExit` from argparse and returns its code so tests can call it directly.

Run: `pytest tests/lfg -q && ruff check tools tests`
Expected: all pass, no lint findings.

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml tools/lfg schemas tests/lfg
git commit -m "Add function spec schema and lfg validate-spec"
```

---

### Task 2: Rule catalogue and the secure Lambda standard

**Files:**
- Create: `standards/rules.yaml`, `standards/secure-lambda-standard.md`, `tools/lfg/rules.py`
- Test: `tests/lfg/test_rules.py`

**Interfaces:**
- Produces:
  - `lfg.rules.Rule` frozen dataclass: `id: str`, `title: str`, `klass: str` (`deny`, `require` or `accept`), `severity: str` (`critical`, `high`, `medium`, `low`), `cwe: str | None`, `enforced_by: str` (`policy-check`, `scanner` or `review`), `summary: str`
  - `lfg.rules.Catalogue` frozen dataclass: `rules: dict[str, Rule]`, `enabled_triggers: frozenset[str]`, `allowed_resource_types: frozenset[str]`, `wildcard_only_actions: tuple[str, ...]`, `sensitive_actions: tuple[str, ...]`, `secret_name_pattern: str`, `secret_name_safe_suffixes: tuple[str, ...]`
  - `lfg.rules.load_catalogue(path: Path | None = None) -> Catalogue`; default path is `standards/rules.yaml` at the repository root

- [ ] **Step 1: Write the failing tests**

`tests/lfg/test_rules.py`:

- `load_catalogue()` returns exactly the 26 rule IDs in the table below
- every rule has a `klass`, `severity` and `enforced_by` from the allowed sets, and a non-empty `summary`
- `enabled_triggers == {"schedule", "eventbridge"}`
- `allowed_resource_types == {"AWS::Serverless::Function", "AWS::Logs::LogGroup", "AWS::SQS::Queue", "AWS::SNS::Topic"}`
- every rule ID appears as a heading `### <ID>` in `standards/secure-lambda-standard.md`, and every `### LFG-` heading in that file is a catalogue rule (the two files cannot drift)
- loading a catalogue file with a duplicate rule ID raises `ValueError`

Run: `pytest tests/lfg/test_rules.py -q`
Expected: fails, `lfg.rules` not found.

- [ ] **Step 2: Write `standards/rules.yaml`**

Top-level keys: `enabled_triggers`, `allowed_resource_types`, `wildcard_only_actions`, `sensitive_actions`, `secret_name_pattern`, `secret_name_safe_suffixes`, `rules`.

Rules:

| ID | Class | Severity | CWE | Enforced by | Summary |
|---|---|---|---|---|---|
| LFG-TPL-001 | deny | high | CWE-1188 | policy-check | Only resource types on the allow-list may appear, with exactly one `AWS::Serverless::Function` |
| LFG-TPL-002 | deny | high | CWE-1188 | policy-check | A `Globals` section is not allowed |
| LFG-NAME-001 | require | medium | none | policy-check | `FunctionName` is `lfg-${Stage}-<spec name>` |
| LFG-SPEC-001 | deny | high | CWE-269 | policy-check | Every IAM action in the template is declared in the spec |
| LFG-SPEC-002 | deny | medium | none | policy-check | Runtime, architecture, timeout, memory and trigger in the template match the spec |
| LFG-TRG-001 | deny | medium | none | policy-check | The trigger type is enabled in this release |
| LFG-RA-001 | deny | high | none | policy-check | A risk acceptance names a known rule of class `accept` and has not expired |
| LFG-IAM-001 | deny | critical | CWE-732 | policy-check | No statement allows the action `*` |
| LFG-IAM-002 | deny | critical | CWE-732 | policy-check | No `NotAction` or `NotResource` |
| LFG-IAM-003 | deny | high | CWE-269 | policy-check | Permissions are inline statements only: no managed policies, no SAM policy templates |
| LFG-IAM-004 | deny | critical | CWE-269 | policy-check | Every role SAM creates carries the `lfg-function-boundary` permissions boundary, and no external `Role` is supplied |
| LFG-IAM-005 | accept | high | CWE-732 | policy-check | `Resource: "*"` is used only with actions that cannot be scoped |
| LFG-IAM-006 | accept | high | CWE-269 | policy-check | Actions that change security controls need a recorded acceptance |
| LFG-IAM-007 | deny | high | CWE-732 | policy-check | Every statement is `Effect: Allow` with explicit `Action` and `Resource` |
| LFG-IAM-008 | accept | medium | CWE-732 | policy-check | A wildcard inside an action name needs a recorded acceptance |
| LFG-SEC-001 | deny | critical | CWE-526 | policy-check | No secret values in environment variables |
| LFG-SEC-002 | deny | critical | CWE-798 | scanner | No hard-coded secrets in source |
| LFG-RUN-001 | deny | high | CWE-1104 | policy-check | The runtime is on the allowed list |
| LFG-RUN-002 | accept | low | CWE-400 | policy-check | A timeout above 60 seconds needs a recorded acceptance |
| LFG-LOG-001 | require | medium | CWE-778 | policy-check | A log group with the spec's retention is declared and used |
| LFG-REL-001 | require | medium | CWE-755 | policy-check | Asynchronous triggers have a failure destination |
| LFG-DEP-001 | require | high | CWE-1357 | policy-check | Dependencies are pinned to exact versions with hashes |
| LFG-NET-001 | accept | high | CWE-306 | policy-check | A function URL without IAM authentication needs a recorded acceptance |
| LFG-COD-001 | require | high | CWE-20 | review | The handler validates the event before using it |
| LFG-COD-002 | require | medium | CWE-532 | review | Logs do not contain whole events, secrets or personal data |
| LFG-COD-003 | deny | high | CWE-94 | scanner | No dynamic code execution, shell invocation or unsafe deserialisation |

Lists:

- `wildcard_only_actions`: `ec2:Describe*`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListUsers`, `xray:PutTraceSegments`, `xray:PutTelemetryRecords`. Add a comment that each entry must be confirmed against the AWS Service Authorization Reference; Lab 02 asks Pratik to do so.
- `sensitive_actions`: `iam:Attach*`, `iam:Create*`, `iam:Delete*`, `iam:Detach*`, `iam:Put*`, `iam:Update*`, `iam:PassRole`, `ec2:AuthorizeSecurityGroup*`, `ec2:RevokeSecurityGroup*`, `ec2:ModifySecurityGroupRules`, `s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`, `s3:PutBucketAcl`, `s3:PutBucketPublicAccessBlock`, `kms:ScheduleKeyDeletion`, `kms:PutKeyPolicy`, `kms:DisableKey`, `lambda:AddPermission`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:Delete*`
- `secret_name_pattern`: `(?i)(password|passwd|secret|token|api_?key|private_?key|credential)`
- `secret_name_safe_suffixes`: `_ARN`, `_NAME`, `_PARAM`, `_ID`

- [ ] **Step 3: Write `standards/secure-lambda-standard.md`**

An introduction (what the standard is for, the three rule classes, how a risk acceptance works, who enforces what), then one `### <ID>` section per rule in catalogue order. Each section has: the rule in one sentence, why it matters, a compliant snippet, a non-compliant snippet, and its CWE. Where relevant, name the OWASP Serverless Top 10 category and the AWS Well-Architected security pillar question. Do not quote either source at length.

- [ ] **Step 4: Implement `tools/lfg/rules.py`**

Run: `pytest tests/lfg/test_rules.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add standards tools/lfg/rules.py tests/lfg/test_rules.py
git commit -m "Add rule catalogue and secure Lambda standard"
```

---

### Task 3: Template loader, policy engine and template-level rules

**Files:**
- Create: `tools/lfg/cfn_yaml.py`, `tools/lfg/policy/__init__.py`, `tools/lfg/policy/acceptance.py`, `tools/lfg/policy/template_rules.py`
- Create: `tests/lfg/fixtures/good/template.yaml`, `tests/lfg/fixtures/good/src/app.py`, `tests/lfg/fixtures/good/src/requirements.txt`
- Test: `tests/lfg/test_cfn_yaml.py`, `tests/lfg/test_policy_engine.py`, `tests/lfg/test_policy_template.py`
- Modify: `tests/lfg/conftest.py` (add the `good_template` fixture and the `rule_ids` helper)

**Interfaces:**
- Consumes: `lfg.rules.load_catalogue`, `Catalogue`, `Rule` (Task 2)
- Produces:
  - `lfg.cfn_yaml.TemplateLoadError(Exception)`
  - `lfg.cfn_yaml.load_template(path: Path) -> dict`. Short-form tags become long form: `!Ref X` gives `{"Ref": "X"}`; `!GetAtt A.B` gives `{"Fn::GetAtt": ["A", "B"]}`; any other `!Name value` gives `{"Fn::Name": value}`. Raises `TemplateLoadError` for a missing file, invalid YAML or a non-mapping top level.
  - `lfg.policy.Violation` frozen dataclass: `rule_id: str`, `message: str`, `location: str`, `accepted: bool = False`, `accepted_until: str | None = None`
  - `lfg.policy.check(spec: dict, template: dict, source_dir: Path, today: datetime.date, catalogue: Catalogue | None = None) -> list[Violation]`, sorted by `(rule_id, location)`
  - `lfg.policy.blocking(violations: list[Violation]) -> list[Violation]`: those with `accepted` false
  - `lfg.policy.template_rules.get_function(template: dict) -> tuple[str, dict] | None`: logical ID and `Properties` of the single `AWS::Serverless::Function`, or `None`
  - `lfg.policy.template_rules.check_template(spec, template, catalogue) -> list[Violation]`
  - `lfg.policy.acceptance.apply(violations, spec, catalogue, today) -> list[Violation]`: marks accepted violations and appends any `LFG-RA-001` violations
  - Each rule module exposes one `check_*` function returning raw, unaccepted violations. `check()` calls every module, then `acceptance.apply`.
  - pytest: `good_template` fixture (fresh dict), helper `rule_ids(violations) -> set[str]` returning the IDs of blocking violations

- [ ] **Step 1: Write the good template fixture**

`tests/lfg/fixtures/good/template.yaml`:

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Transform: AWS::Serverless-2016-10-31
Description: Report IAM access keys older than the allowed age.

Parameters:
  Stage:
    Type: String
    AllowedValues: [dev, prod]

Resources:
  Function:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub lfg-${Stage}-iam-key-age-audit
      CodeUri: src/
      Handler: app.handler
      Runtime: python3.13
      Architectures: [arm64]
      Timeout: 30
      MemorySize: 256
      PermissionsBoundary: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary
      LoggingConfig:
        LogGroup: !Ref LogGroup
        LogFormat: JSON
      DeadLetterQueue:
        Type: SQS
        TargetArn: !GetAtt FailureQueue.Arn
      Environment:
        Variables:
          MAX_KEY_AGE_DAYS: "90"
          ALERT_TOPIC_ARN: !Ref AlertTopic
      Policies:
        - Version: "2012-10-17"
          Statement:
            - Effect: Allow
              Action:
                - iam:GenerateCredentialReport
                - iam:GetCredentialReport
              Resource: "*"
            - Effect: Allow
              Action: sns:Publish
              Resource: !Ref AlertTopic
      Events:
        Daily:
          Type: ScheduleV2
          Properties:
            ScheduleExpression: rate(1 day)
            ScheduleExpressionTimezone: UTC
            PermissionsBoundary: !Sub arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary

  LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/lambda/lfg-${Stage}-iam-key-age-audit
      RetentionInDays: 30

  FailureQueue:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  AlertTopic:
    Type: AWS::SNS::Topic
```

`src/app.py`: a three-line `handler(event, context)` returning `{"ok": True}`. `src/requirements.txt`: empty. The real function is written in Plan 2.

- [ ] **Step 2: Write the failing loader tests**

`tests/lfg/test_cfn_yaml.py`:

- the good template loads, and `Resources.Function.Properties.FunctionName == {"Fn::Sub": "lfg-${Stage}-iam-key-age-audit"}`
- `LoggingConfig.LogGroup == {"Ref": "LogGroup"}`
- `DeadLetterQueue.TargetArn == {"Fn::GetAtt": ["FailureQueue", "Arn"]}`
- `!Join ["-", [a, b]]` loads as `{"Fn::Join": ["-", ["a", "b"]]}`
- `TemplateLoadError` for a missing file, for `": :\n- ["`, and for a top-level list

- [ ] **Step 3: Implement `tools/lfg/cfn_yaml.py`**

Subclass `yaml.SafeLoader` and register a multi-constructor for the `!` prefix that builds the long form from scalar, sequence or mapping nodes.

Run: `pytest tests/lfg/test_cfn_yaml.py -q`
Expected: all pass.

- [ ] **Step 4: Write the failing engine and acceptance tests**

`tests/lfg/test_policy_engine.py`, all with `today = date(2026, 11, 16)`:

- `check(good_spec, good_template, good_dir / "src", today)` returns `[]`
- `timeout = 120` in both spec and template, no acceptance: `rule_ids == {"LFG-RUN-002"}`
- the same, with an acceptance for `LFG-RUN-002` expiring `2026-12-31`: `rule_ids == set()`, and the returned list holds one violation with `accepted is True` and `accepted_until == "2026-12-31"`
- acceptance expiring `2026-11-16` (today): still accepted
- acceptance expiring `2026-11-15`: `rule_ids == {"LFG-RUN-002", "LFG-RA-001"}`
- an acceptance for `LFG-IAM-001` (class `deny`): `LFG-RA-001` is reported
- an acceptance for `LFG-XYZ-999` (unknown): `LFG-RA-001` is reported
- an acceptance for `LFG-RUN-002` when nothing violates it: no violation (an unused acceptance is harmless)
- results are sorted by `(rule_id, location)`

- [ ] **Step 5: Write the failing template-rule tests**

`tests/lfg/test_policy_template.py`: parametrised; mutate deep copies of the good spec and template; assert `rule_ids(...) == expected`.

| Test id | Mutation | Expected |
|---|---|---|
| `globals_present` | template gains `Globals: {Function: {Timeout: 3}}` | `{LFG-TPL-002}` |
| `raw_lambda_function` | add a resource of type `AWS::Lambda::Function` | `{LFG-TPL-001}` |
| `standalone_iam_role` | add a resource of type `AWS::IAM::Role` | `{LFG-TPL-001}` |
| `two_functions` | duplicate `Function` as `Function2` | `{LFG-TPL-001}` |
| `no_function` | delete `Function` | `{LFG-TPL-001}` |
| `no_resources_key` | delete `Resources` | `{LFG-TPL-001}` |
| `name_literal` | `FunctionName = "my-function"` | `{LFG-NAME-001}` |
| `name_wrong_suffix` | `FunctionName = {"Fn::Sub": "lfg-${Stage}-other"}` | `{LFG-NAME-001}` |
| `name_missing` | delete `FunctionName` | `{LFG-NAME-001}` |
| `runtime_mismatch` | template `Runtime = "python3.14"`, spec unchanged | `{LFG-SPEC-002}` |
| `runtime_not_allowed` | template `Runtime = "python3.9"` | `{LFG-RUN-001, LFG-SPEC-002}` |
| `arch_mismatch` | template `Architectures = ["x86_64"]` | `{LFG-SPEC-002}` |
| `timeout_mismatch` | template `Timeout = 31` | `{LFG-SPEC-002}` |
| `memory_mismatch` | template `MemorySize = 512` | `{LFG-SPEC-002}` |
| `event_type_mismatch` | the event's `Type = "EventBridgeRule"` | `{LFG-SPEC-002}` |
| `no_events` | delete `Events` | `{LFG-SPEC-002}` |
| `two_events` | add a second `ScheduleV2` event | `{LFG-SPEC-002}` |
| `schedule_expression_mismatch` | event `ScheduleExpression = "rate(1 hour)"` | `{LFG-SPEC-002}` |
| `trigger_not_enabled` | spec `trigger = {type: http, method: GET, path: /x, auth: iam}`, event `Type = "HttpApi"` | `{LFG-TRG-001}` |

When `get_function` returns `None`, `check` reports `LFG-TPL-001` and skips the per-function modules, so `no_function` yields exactly one rule ID.

- [ ] **Step 6: Implement the engine, `acceptance.py` and `template_rules.py`**

`template_rules.py` owns `LFG-TPL-001`, `LFG-TPL-002`, `LFG-NAME-001`, `LFG-SPEC-002`, `LFG-TRG-001`, `LFG-RUN-001` and `LFG-RUN-002`. `LFG-RUN-002` fires when the template `Timeout` exceeds 60.

Trigger-to-event mapping: `schedule` to `ScheduleV2`, `eventbridge` to `EventBridgeRule`. For `eventbridge`, the event's `Properties.Pattern` must equal the spec's `trigger.pattern`. `LFG-NAME-001` compares against exactly `{"Fn::Sub": "lfg-${Stage}-" + spec["name"]}`. `LFG-TRG-001` takes priority: when the trigger type is not enabled, do not also report `LFG-SPEC-002` for the event.

`location` strings follow the template path, for example `template.yaml:Resources.Function.Properties.Timeout`; spec-side problems use `function.spec.yaml:<dotted path>`.

Run: `pytest tests/lfg -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add tools/lfg tests/lfg
git commit -m "Add template loader, policy engine and template rules"
```

---

### Task 4: IAM rules

**Files:**
- Create: `tools/lfg/policy/iam_rules.py`
- Modify: `tools/lfg/policy/__init__.py` (call the new module from `check`)
- Test: `tests/lfg/test_policy_iam.py`

**Interfaces:**
- Consumes: `get_function`, `Violation`, `Catalogue` (Tasks 2 and 3)
- Produces: `lfg.policy.iam_rules.check_iam(spec: dict, template: dict, catalogue: Catalogue) -> list[Violation]`

- [ ] **Step 1: Write the failing tests**

`tests/lfg/test_policy_iam.py`: parametrised as in Task 3. "Statement 0" is the credential-report statement of the good template. Where a row adds or changes an action, make the same change in the spec unless the row says otherwise, so `LFG-SPEC-001` does not fire by accident. The bare `*` action is the exception: it is never added to the spec.

| Test id | Mutation | Expected |
|---|---|---|
| `action_star` | statement 0 `Action = "*"` | `{LFG-IAM-001}` |
| `action_star_in_list` | statement 0 `Action = ["iam:GetCredentialReport", "*"]` | `{LFG-IAM-001}` |
| `not_action` | statement 0 uses `NotAction` in place of `Action` | `{LFG-IAM-002}` |
| `not_resource` | statement 0 uses `NotResource` in place of `Resource` | `{LFG-IAM-002}` |
| `managed_policy_name` | `Policies = ["AdministratorAccess"]` | `{LFG-IAM-003}` |
| `managed_policy_arn` | `Policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]` | `{LFG-IAM-003}` |
| `policies_is_string` | `Policies = "AWSLambdaBasicExecutionRole"` | `{LFG-IAM-003}` |
| `sam_policy_template` | `Policies = [{"S3ReadPolicy": {"BucketName": "b"}}]` | `{LFG-IAM-003}` |
| `no_boundary` | delete `PermissionsBoundary` from the function | `{LFG-IAM-004}` |
| `wrong_boundary` | `PermissionsBoundary = "arn:aws:iam::aws:policy/PowerUserAccess"` | `{LFG-IAM-004}` |
| `external_role` | add `Role = {"Fn::GetAtt": ["Other", "Arn"]}` | `{LFG-IAM-004}` |
| `schedule_no_boundary` | delete `PermissionsBoundary` from the `ScheduleV2` event | `{LFG-IAM-004}` |
| `star_resource_scopable` | statement 1 (`sns:Publish`) `Resource = "*"` | `{LFG-IAM-005}` |
| `star_resource_in_list` | statement 1 `Resource = ["*"]` | `{LFG-IAM-005}` |
| `star_resource_wildcard_only` | the unmodified good template | `set()` |
| `describe_wildcard_only` | add a statement `ec2:DescribeSecurityGroups` on `*`, declared in the spec | `set()` |
| `sensitive_action` | add a statement `ec2:RevokeSecurityGroupIngress` on a specific ARN, declared in the spec | `{LFG-IAM-006}` |
| `sensitive_action_case` | the same with `EC2:revokesecuritygroupingress` in both files | `{LFG-IAM-006}` |
| `pass_role` | add a statement `iam:PassRole` on a specific ARN, declared | `{LFG-IAM-006}` |
| `effect_deny` | statement 0 `Effect = "Deny"` | `{LFG-IAM-007}` |
| `effect_missing` | delete statement 0 `Effect` | `{LFG-IAM-007}` |
| `resource_missing` | delete statement 0 `Resource` | `{LFG-IAM-007}` |
| `statement_not_mapping` | `Statement = ["oops"]` | `{LFG-IAM-007}` |
| `statement_is_mapping` | `Statement` is the single statement mapping, not a list | `set()` |
| `action_wildcard_suffix` | add `s3:Get*` on a specific ARN, declared as `s3:Get*` | `{LFG-IAM-008}` |
| `service_star` | add `s3:*` on a specific ARN, declared as `s3:*` | `{LFG-IAM-006, LFG-IAM-008}` |
| `wildcard_covers_sensitive` | add `iam:Pass*` on a specific ARN, declared | `{LFG-IAM-006, LFG-IAM-008}` |
| `undeclared_action` | add `s3:GetObject` on a specific ARN to the template only | `{LFG-SPEC-001}` |
| `declared_case_differs` | spec declares `SNS:publish`, template has `sns:Publish` | `set()` |
| `no_policies` | delete `Policies` from the template and `permissions = []` in the spec | `set()` |

Plus acceptance tests through `check`:

- `sensitive_action` with a valid acceptance for `LFG-IAM-006`: `rule_ids == set()`
- `action_star` with an acceptance for `LFG-IAM-001`: `rule_ids == {"LFG-IAM-001", "LFG-RA-001"}`

Run: `pytest tests/lfg/test_policy_iam.py -q`
Expected: fails, `iam_rules` not found.

- [ ] **Step 2: Implement `check_iam`**

Decisions the tests do not fully determine:

- Normalise first: `Policies` must be a list whose every item is a mapping with a `Statement` key; anything else is `LFG-IAM-003`, and that item is not inspected further. `Statement` may be a mapping or a list of mappings. `Action` and `Resource` may each be a string or a list.
- All action comparisons are lowercase.
- A statement that fails `LFG-IAM-002` or `LFG-IAM-007` is reported once and not inspected by any other rule.
- The bare `*` action is reported as `LFG-IAM-001` only. It is left out of the `LFG-IAM-005`, `LFG-IAM-006`, `LFG-IAM-008` and `LFG-SPEC-001` evaluations.
- `LFG-IAM-005` fires when a statement's resources include the literal `"*"` and at least one of its actions matches no `wildcard_only_actions` pattern (`fnmatch`, lowercase).
- `LFG-IAM-006` fires for an action when it matches a `sensitive_actions` pattern, or when the action contains `*` and its literal prefix before the first `*` is a prefix of, or is prefixed by, the literal prefix of any sensitive pattern. This is how `iam:Pass*` and `iam:*` are caught.
- `LFG-IAM-008` fires for any action containing `*` other than the bare `*` (which is `LFG-IAM-001`), unless it matches a `wildcard_only_actions` pattern exactly.
- `LFG-SPEC-001` fires for each template action whose lowercase form is absent from the lowercase union of the spec's `permissions[].actions`.
- A boundary value is valid when its JSON serialisation contains `policy/lfg-function-boundary`.
- One violation per offending statement per rule, located at `template.yaml:Resources.<LogicalId>.Properties.Policies[<i>].Statement[<j>]`.

Run: `pytest tests/lfg -q`
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add tools/lfg/policy tests/lfg/test_policy_iam.py
git commit -m "Add IAM policy rules"
```

---

### Task 5: Configuration rules and `lfg policy-check`

**Files:**
- Create: `tools/lfg/policy/config_rules.py`
- Modify: `tools/lfg/policy/__init__.py`, `tools/lfg/cli.py`
- Test: `tests/lfg/test_policy_config.py`, `tests/lfg/test_cli_policy_check.py`

**Interfaces:**
- Consumes: everything from Tasks 1 to 4
- Produces:
  - `lfg.policy.config_rules.check_config(spec: dict, template: dict, source_dir: Path, catalogue: Catalogue) -> list[Violation]`
  - CLI: `lfg policy-check <function_dir> [--today YYYY-MM-DD] [--format text|json]`

- [ ] **Step 1: Write the failing rule tests**

`tests/lfg/test_policy_config.py`, parametrised as before:

| Test id | Mutation | Expected |
|---|---|---|
| `env_secret_name` | template `Variables.DB_PASSWORD = "hunter2"` | `{LFG-SEC-001}` |
| `env_secret_name_ref` | template `Variables.API_TOKEN = {"Ref": "X"}` | `{LFG-SEC-001}` |
| `env_safe_suffix` | template `Variables.DB_PASSWORD_PARAM = "/lfg/db"` | `set()` |
| `env_secret_arn` | template `Variables.SLACK_TOKEN_ARN = {"Ref": "X"}` | `set()` |
| `spec_env_secret_name` | spec `environment.API_KEY = "abc"` | `{LFG-SEC-001}` |
| `no_logging_config` | delete `LoggingConfig` | `{LFG-LOG-001}` |
| `log_group_literal` | `LoggingConfig.LogGroup = "/aws/lambda/x"` | `{LFG-LOG-001}` |
| `log_group_missing_resource` | delete the `LogGroup` resource | `{LFG-LOG-001}` |
| `retention_missing` | delete `RetentionInDays` | `{LFG-LOG-001}` |
| `retention_mismatch` | `RetentionInDays = 7` | `{LFG-LOG-001}` |
| `no_failure_destination` | delete `DeadLetterQueue` | `{LFG-REL-001}` |
| `on_failure_destination` | replace `DeadLetterQueue` with `EventInvokeConfig.DestinationConfig.OnFailure = {Type: SQS, Destination: {"Fn::GetAtt": ["FailureQueue", "Arn"]}}` | `set()` |
| `spec_says_none` | spec `failure_destination = "none"`, `DeadLetterQueue` kept | `{LFG-REL-001}` |
| `function_url_none` | add `FunctionUrlConfig = {AuthType: NONE}` | `{LFG-NET-001}` |
| `function_url_iam` | add `FunctionUrlConfig = {AuthType: AWS_IAM}` | `set()` |

`LFG-DEP-001` tests write `requirements.txt` in `good_dir / "src"`:

| Test id | File content | Expected |
|---|---|---|
| `deps_empty` | empty | `set()` |
| `deps_missing_file` | file deleted | `set()` |
| `deps_comments_only` | `# nothing\n\n` | `set()` |
| `deps_pinned_hashed` | `aws-lambda-powertools==3.2.0 \\\n    --hash=sha256:` followed by 64 hex characters | `set()` |
| `deps_unpinned` | `requests` | `{LFG-DEP-001}` |
| `deps_range` | `requests>=2.0` | `{LFG-DEP-001}` |
| `deps_pinned_no_hash` | `requests==2.32.3` | `{LFG-DEP-001}` |
| `deps_include` | `-r other.txt` | `{LFG-DEP-001}` |
| `deps_url` | `git+https://github.com/x/y.git` | `{LFG-DEP-001}` |

Run: `pytest tests/lfg/test_policy_config.py -q`
Expected: fails, `config_rules` not found.

- [ ] **Step 2: Implement `check_config`**

- `LFG-SEC-001`: an environment variable name matching `secret_name_pattern` and not ending in a safe suffix, whatever its value. Checked in the template's `Environment.Variables` and the spec's `environment`.
- `LFG-LOG-001`: `LoggingConfig.LogGroup` must be `{"Ref": <id>}` where `<id>` is an `AWS::Logs::LogGroup` resource whose `RetentionInDays` equals the spec's `log_retention_days`.
- `LFG-REL-001`: applies when the spec trigger type is `schedule` or `eventbridge`. Requires `DeadLetterQueue` or `EventInvokeConfig.DestinationConfig.OnFailure`, and a spec `failure_destination` other than `none`.
- `LFG-NET-001`: `FunctionUrlConfig.AuthType` other than `AWS_IAM`.
- `LFG-DEP-001`: join backslash-continued lines, drop blank lines and comments; each remaining requirement must contain `==` and `--hash=sha256:`, and must not start with `-` or contain `://`.

Run: `pytest tests/lfg -q`
Expected: all pass.

- [ ] **Step 3: Write the failing CLI tests**

`tests/lfg/test_cli_policy_check.py`:

- the good directory: prints `OK: iam-key-age-audit (0 violations)`, returns `0`
- template `Timeout` and spec `timeout` rewritten to `120`: returns `1`; stdout contains `LFG-RUN-002` and `template.yaml:Resources.Function.Properties.Timeout`
- the same with a valid acceptance and `--today 2026-11-16`: returns `0`; stdout contains `ACCEPTED until`
- a spec that fails schema validation: returns `1`, prints the schema errors and does not run the policy checks
- `template.yaml` missing: returns `2`, stderr names the file, no `Traceback`
- `template.yaml` containing invalid YAML: returns `2`
- `--format json` on a violating directory: stdout parses as JSON with keys `function`, `blocking` (integer) and `violations` (a list of objects with `rule_id`, `message`, `location`, `accepted`, `accepted_until`)
- `--today not-a-date`: returns `2`

- [ ] **Step 4: Implement the `policy-check` subcommand**

Text output is one line per violation: `<rule_id>  <location>  <message>`, with ` [ACCEPTED until <date>]` appended for accepted ones, then a summary line `BLOCKED: <n> violation(s)` or the `OK:` line. `--today` defaults to the current date.

Run: `pytest -q && ruff check tools tests`
Expected: all pass, no lint findings.

- [ ] **Step 5: Commit**

```bash
git add tools/lfg tests/lfg
git commit -m "Add configuration rules and lfg policy-check"
```

---

### Task 6: Lab tooling (`lfg labcheck` and the skeleton script)

**Files:**
- Create: `labs/manifest.yaml`, `tools/lfg/labcheck.py`, `tools/dev/skeletonise.py`
- Modify: `tools/lfg/cli.py`
- Test: `tests/lfg/test_labcheck.py`, `tests/dev/test_skeletonise.py`

**Interfaces:**
- Produces:
  - Manifest shape:
    ```yaml
    labs:
      "02":
        title: Function spec and policy checker
        dir: labs/02-spec-and-policy
        owned: [schemas/function-spec.schema.json, tools/lfg/spec.py]
        checks: [tests/lfg/test_spec.py]
    ```
  - `lfg.labcheck.load_manifest(root: Path) -> dict`
  - `lfg.labcheck.run(lab: str, root: Path, extra_args: list[str] | None = None) -> int`: runs `pytest` on the lab's `checks`; returns pytest's exit code, or `2` for an unknown lab
  - CLI: `lfg labcheck <NN>`, and `lfg labcheck --list`, which prints one line per lab as `<NN>  <title>`
  - `tools/dev/skeletonise.py`: `apply(root: Path) -> list[Path]` copies `<dir>/skeleton/<path>` over `<path>` for every owned file of every lab, deletes each `skeleton/` directory and returns the replaced paths. It raises `FileNotFoundError` naming the path if an owned file has no skeleton. Running the file as a script applies it to the repository root and prints the replaced paths.

- [ ] **Step 1: Write the failing tests**

`tests/lfg/test_labcheck.py`, each building a miniature repository in `tmp_path` with a manifest and trivial check files:

- a lab whose only check passes returns `0`
- a lab whose check fails returns `1`
- an unknown lab returns `2`
- `main(["labcheck", "--list"])` prints the titles from the real manifest

`tests/dev/test_skeletonise.py`, again in `tmp_path`:

- after `apply`, an owned file's content equals its skeleton's content
- the `skeleton/` directory no longer exists
- a file not listed as owned is unchanged
- an owned file with no skeleton raises `FileNotFoundError` whose message contains the path

- [ ] **Step 2: Implement `labcheck.py`, the CLI wiring and `skeletonise.py`**

`labcheck.run` invokes `pytest` in a subprocess (`sys.executable -m pytest`) with the repository root as working directory, so the check run cannot interfere with an outer pytest session.

Write `labs/manifest.yaml` with entries for labs `00`, `01` and `02`. For now give `00` and `01` empty `owned` and `checks` lists; Tasks 7 and 8 fill them in.

Run: `pytest -q`
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add labs/manifest.yaml tools tests
git commit -m "Add lab check runner and skeleton tooling"
```

---

### Task 7: Labs 00 and 01

**Files:**
- Create: `labs/00-workstation/README.md`, `labs/00-workstation/answers.md`, `labs/00-workstation/skeleton/labs/00-workstation/answers.md`, `labs/checks/test_lab00.py`
- Create: `labs/01-threat-model/README.md`, `labs/01-threat-model/skeleton/docs/threat-model.md`, `labs/checks/test_lab01.py`, `docs/threat-model.md`
- Modify: `labs/manifest.yaml`

`labs/checks/` stays out of the pytest `testpaths`, so a plain `pytest` run never depends on the machine's installed tools. Lab checks run only through `lfg labcheck`.

**Interfaces:**
- Consumes: the manifest and `labcheck` (Task 6)
- Produces: manifest entries: lab `00` owns `labs/00-workstation/answers.md`, checked by `labs/checks/test_lab00.py`; lab `01` owns `docs/threat-model.md`, checked by `labs/checks/test_lab01.py`

**Lab brief format (used by every lab in every plan).** Sections in this order: Goal; Why this matters (first principles, no more than 200 words); Before you start; Research questions (questions only, with no answers in the brief); Tasks (numbered, with bash command blocks where a command is needed); Hints (each inside a collapsed `<details>` block); Acceptance (`lfg labcheck <NN>`); Debrief (three to five questions to answer in his own words); Interview questions (three); Maps to (AWS Solutions Architect Associate domains, and MITRE ATT&CK or OWASP entries where they apply); Boss challenge (one harder, optional task).

- [ ] **Step 1: Write the Lab 00 check**

`labs/checks/test_lab00.py`:

- `test_tools_on_path`, parametrised over `git`, `python3`, `aws`, `sam`, `terraform`, `docker`, `gh`, `claude`: `shutil.which(tool)` is not `None`
- `test_python_version`: `sys.version_info >= (3, 12)`
- `test_answers_filled`: `labs/00-workstation/answers.md` contains the six headings `## Q1` to `## Q6`, and the text under each heading is at least 40 characters and does not contain `TODO`
- `test_not_root` (marked `aws`, skipped unless `AWS_PROFILE` or `AWS_ACCESS_KEY_ID` is set): the ARN from `aws sts get-caller-identity` does not end in `:root`
- `test_budget_exists` (marked `aws`): `aws budgets describe-budgets` for the caller's account returns at least one budget

- [ ] **Step 2: Write the Lab 00 brief and answer files**

The brief covers: installing WSL2 with Ubuntu 24.04 and working inside the Linux filesystem; installing Git, Python 3.12, AWS CLI v2, SAM CLI, Terraform, Docker Desktop with WSL integration, GitHub CLI and Claude Code; cloning the repository and `pip install -e ".[dev]"`; `aws configure sso` or an equivalent non-root profile for `eu-west-1`; a monthly AWS budget alarm; spend limits in the Anthropic Console and the OpenAI dashboard.

The six questions in `answers.md`, each to be answered from primary documentation with the URL he used:

1. Which Python runtimes does Lambda currently support, and what are their deprecation dates? Should this project move its default from `python3.13` to `python3.14`?
2. What is the exact `sub` claim GitHub sends to AWS for a workflow job that targets an environment named `prod`?
3. Why is his everyday AWS identity not the root user, and what can only root do?
4. What does Lambda's free tier cover each month, and which resource in this project is most likely to cost money first?
5. For each entry in `wildcard_only_actions` in `standards/rules.yaml`, does the Service Authorization Reference confirm the action cannot be scoped to a resource?
6. Can his OpenAI API account run `npx @openai/codex-security scan --dry-run` on this repository, and what does the dry run report?

The reference `answers.md` answers what can be answered without his accounts, and marks questions 2, 5 and 6 as needing his own verification, giving the reason. The skeleton `answers.md` has the six headings, each followed by `TODO`.

- [ ] **Step 3: Write the Lab 01 check**

`labs/checks/test_lab01.py`, reading `docs/threat-model.md`:

- contains the headings `## System overview`, `## Data flow diagram`, `## Assets`, `## Trust boundaries`, `## Threats`, `## Top risks`
- the `## Data flow diagram` section contains a fenced code block
- the `## Threats` section contains a Markdown table with at least 15 data rows
- every data row has a non-empty cell in the columns `ID`, `Component`, `STRIDE`, `Threat`, `Mitigation`, `Status`
- the `STRIDE` column, taken across all rows, covers all six categories: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege
- at least one row's `Threat` cell mentions `prompt injection` (case-insensitive)
- no cell contains `TODO`

- [ ] **Step 4: Write the reference threat model, the Lab 01 brief and its skeleton**

`docs/threat-model.md` is the reference solution: the system from section 5 of the design, a text data-flow diagram, assets (the two API keys, the deploy roles, the signing profile, the evidence bucket, the generated code), trust boundaries (developer machine, GitHub-hosted runner, the LLM providers, AWS), at least 20 threats with mitigations that point at design sections or rule IDs, and the five top risks.

The brief has Pratik draw the diagram and write his own table before the build starts. Its research questions cover STRIDE, trust boundaries, the PromptPwnd research, and the difference between `pull_request` and `pull_request_target`. The skeleton `docs/threat-model.md` has the six headings and an empty table with the column headers.

- [ ] **Step 5: Update the manifest and verify**

Run: `lfg labcheck 01`
Expected: passes against the reference threat model.

Run: `lfg labcheck 00`
Expected in the build session: `test_answers_filled` and `test_python_version` pass; the tools-on-path tests fail for tools not installed there (`aws`, `sam`, `terraform`, `claude`); the `aws` tests are skipped. Record this in the commit message body. The check is confirmed on Pratik's machine.

- [ ] **Step 6: Commit**

```bash
git add labs docs/threat-model.md
git commit -m "Add Labs 00 and 01 with checks and reference threat model"
```

---

### Task 8: Lab 02, README, learning roadmap and the learner branch

**Files:**
- Create: `labs/02-spec-and-policy/README.md`, and `labs/02-spec-and-policy/skeleton/` holding skeletons of `schemas/function-spec.schema.json`, `tools/lfg/spec.py`, `tools/lfg/policy/__init__.py`, `tools/lfg/policy/acceptance.py`, `tools/lfg/policy/template_rules.py`, `tools/lfg/policy/iam_rules.py`, `tools/lfg/policy/config_rules.py`
- Create: `docs/learning-roadmap.md`
- Modify: `README.md`, `labs/manifest.yaml`

**Interfaces:**
- Consumes: everything above
- Produces: manifest entry for lab `02`, owning the seven files above and checked by `tests/lfg/test_spec.py`, `tests/lfg/test_cli_validate_spec.py`, `tests/lfg/test_policy_engine.py`, `tests/lfg/test_policy_template.py`, `tests/lfg/test_policy_iam.py`, `tests/lfg/test_policy_config.py` and `tests/lfg/test_cli_policy_check.py`

- [ ] **Step 1: Write the Lab 02 skeletons**

Each Python skeleton keeps the module docstring, imports, dataclasses and every public signature from the Interfaces blocks of Tasks 1, 3, 4 and 5, with a docstring stating the contract and the rule IDs it serves. Each body is `raise NotImplementedError("Lab 02, part <A-D>")`. The schema skeleton is a valid JSON Schema containing only `$schema`, `title`, `type: object` and a `description` that says where the field list is.

The skeletons must import cleanly: `python -c "import lfg.policy, lfg.spec"` succeeds on the learner branch, so the CLI still starts and the tests fail on assertions or `NotImplementedError`, not at collection.

- [ ] **Step 2: Write the Lab 02 brief**

Four parts, each with its own acceptance command:

- **A, the spec schema** (`pytest tests/lfg/test_spec.py tests/lfg/test_cli_validate_spec.py`)
- **B, the engine, risk acceptances and template rules** (`pytest tests/lfg/test_policy_engine.py tests/lfg/test_policy_template.py`)
- **C, the IAM rules** (`pytest tests/lfg/test_policy_iam.py`)
- **D, the configuration rules and the command** (`pytest tests/lfg/test_policy_config.py tests/lfg/test_cli_policy_check.py`)

Research questions include: why the spec and not the template is the source of truth; what "fail closed" means and where this checker must do it; how IAM evaluates a permissions boundary together with an identity policy; why SAM policy templates are refused here; why a deploy role that can create roles is dangerous and which condition key contains it. The boss challenge: add a new rule end to end (catalogue entry, standard section, test, implementation) that refuses a `ReservedConcurrentExecutions` of `0` unless accepted.

- [ ] **Step 3: Write `docs/learning-roadmap.md`**

What to learn beyond the labs, in priority order, each with what to be able to do afterwards, and no course recommendations beyond the two Pratik already named: IAM policy evaluation; CloudFormation and SAM; Python testing; GitHub Actions security and OIDC; Terraform state and modules; OWASP Serverless Top 10; OWASP Top 10 for LLM Applications; STRIDE; CloudTrail and EventBridge for detection; supply-chain controls (signing, bill of materials, provenance). Include a table mapping each lab to Solutions Architect Associate exam domains.

- [ ] **Step 4: Write `README.md`**

Sections: what the project is; the pipeline diagram from the design; current status (which plans are built, as a short table); how to start (`labs/00-workstation`); the lab list; repository layout; a security note that the benchmark fixtures added in Plan 5 are deliberately vulnerable; and an authorship section stating that the lab track, acceptance checks and the `reference-solutions` branch were written by an AI coach (Claude), and that lab work merged to `main` is Pratik's own.

- [ ] **Step 5: Verify the reference branch and push it**

Run: `pytest -q && ruff check . && lfg labcheck 01 && lfg labcheck 02`
Expected: all pass.

```bash
git add -A
git commit -m "Add Lab 02, README and learning roadmap"
git push -u origin reference-solutions
```

- [ ] **Step 6: Generate the learner branch**

```bash
git checkout claude/youthful-sagan-mt8uqi
git checkout reference-solutions -- .
python tools/dev/skeletonise.py
pip install -e ".[dev]"
```

- [ ] **Step 7: Verify the learner branch behaves as a lab**

Run: `python -c "import lfg.policy, lfg.spec, lfg.cli"`
Expected: no error.

Run: `lfg labcheck 02`
Expected: exit code `1`, with failures in all seven check files and no collection errors.

Run: `lfg labcheck 01`
Expected: exit code `1` (the skeleton threat model is empty).

Run: `pytest tests/lfg/test_rules.py tests/lfg/test_cfn_yaml.py tests/lfg/test_labcheck.py tests/dev -q`
Expected: all pass, because coach-owned code is intact.

Run: `git status --short | grep skeleton`
Expected: only deletions; no `skeleton/` directory remains.

- [ ] **Step 8: Commit and push the learner branch**

```bash
git add -A
git commit -m "Add core toolkit skeletons and Labs 00-02"
git push -u origin claude/youthful-sagan-mt8uqi
```
