# Secure Lambda standard

This standard says what an AWS Lambda function must look like before `lfg` allows it to be deployed. A function is described by two files: a YAML function spec (what the function is meant to do and what it may touch) and an AWS SAM template (how it is deployed). The rules below check that the two agree and that the template is safe.

Each rule has an ID of the form `LFG-<AREA>-<NNN>`. An ID is never reused or renumbered. The machine-readable form of every rule is in `rules.yaml`; this document explains the reasoning.

## Rule classes

- **deny**: a violation always fails the check. It cannot be waived.
- **require**: something must be present. Its absence fails the check. It cannot be waived.
- **accept**: a violation fails unless the spec records a risk acceptance for that rule.

## Risk acceptances

A risk acceptance is an entry in the spec's `risk_acceptances` list. It names the rule, gives a justification of at least 20 characters, says who accepted the risk, and carries an expiry date. Only rules of class `accept` can be accepted, and an expired acceptance counts as no acceptance (see LFG-RA-001). Acceptances expire so that a decision made once is reviewed again.

```yaml
risk_acceptances:
  - rule_id: LFG-RUN-002
    justification: The nightly export reads a large file and needs about two minutes.
    accepted_by: platform-team
    expires: 2027-03-31
```

## Who enforces what

- **policy-check**: `lfg` reads the spec and template and decides.
- **scanner**: an automated scan of the source code, run as part of the pipeline.
- **review**: a human reviewer checks the code, because a tool cannot judge it reliably.

Each section gives the rule, why it exists, a compliant and a non-compliant example, and the CWE (Common Weakness Enumeration) number where one applies. Where a rule maps clearly onto an OWASP Serverless Top 10 category, that is named too.

## Template rules

### LFG-TPL-001

**Rule:** Only resource types on the allow-list may appear in the template, and there is exactly one `AWS::Serverless::Function`.

**Why it matters:** Every extra resource type is something the reviewer must understand and something that can grant access. A template that quietly adds an IAM role, a bucket policy or a second function can do things the spec never mentioned. A short allow-list keeps the template small enough to review in full. The allowed types are the function, its log group, an SQS queue and an SNS topic.

Compliant:

```yaml
Resources:
  Function:
    Type: AWS::Serverless::Function
  LogGroup:
    Type: AWS::Logs::LogGroup
```

Non-compliant:

```yaml
Resources:
  Function:
    Type: AWS::Serverless::Function
  Bucket:
    Type: AWS::S3::Bucket
```

**CWE:** CWE-1188 (insecure default initialisation of resource).

### LFG-TPL-002

**Rule:** The template must not have a `Globals` section.

**Why it matters:** `Globals` applies settings to every function in the template without them being written next to the function. A reader checking the function can miss a global that changes its runtime, role or environment variables. Writing every setting on the function itself means what you read is what is deployed.

Compliant:

```yaml
Resources:
  Function:
    Type: AWS::Serverless::Function
    Properties:
      Timeout: 30
```

Non-compliant:

```yaml
Globals:
  Function:
    Timeout: 30
```

**CWE:** CWE-1188.

### LFG-TPL-003

**Rule:** Only allow-listed function attributes, function properties and event properties may appear.

**Why it matters:** Some SAM properties create or change IAM roles (`AssumeRolePolicyDocument`, `DeploymentPreference`), some pull in code the reviewer never sees (`Layers`), and new ones appear with each SAM release. A checker that looks only for the dangerous properties it knows about is out of date the day SAM adds a feature. So the checker works the other way round: the catalogue lists every key the function resource, its `Properties` and its trigger event may have, and anything else is refused until a person has reviewed it and added it to the list. `Role` and `RoleArn` are on the lists only so that LFG-IAM-004 can report them with the right explanation.

Compliant:

```yaml
Properties:
  Timeout: 30
  Policies:
    - Statement: []
```

Non-compliant:

```yaml
Properties:
  Timeout: 30
  AssumeRolePolicyDocument: {}
```

**CWE:** CWE-1188.

### LFG-TPL-004

**Rule:** Only allow-listed top-level sections may appear, and the only transform is `AWS::Serverless-2016-10-31`; `Fn::Transform` is never used.

**Why it matters:** A CloudFormation macro (a `Transform` other than SAM's, or an `Fn::Transform` anywhere in the template) rewrites the template after the checker has read it, so whatever the checker approved is not what is deployed. These templates do not need `Conditions`, `Mappings`, `Rules` or `Hooks`, and each of them widens what a reviewer must read to know what is deployed. The checker therefore accepts only a short list of sections and exactly one transform, written as a single string. The `Parameters` section must be exactly one parameter, `Stage`, of `Type: String` with `AllowedValues: [dev, prod]` and no `Default`, because `${Stage}` is allowed inside resource ARNs and an unconstrained `Stage` could be deployed as `*`.

Compliant:

```yaml
Transform: AWS::Serverless-2016-10-31
```

Non-compliant:

```yaml
Transform:
  - AWS::Serverless-2016-10-31
  - SomeMacro
```

**CWE:** CWE-829.

### LFG-NAME-001

**Rule:** `FunctionName` is `lfg-${Stage}-<spec name>`.

**Why it matters:** The deploy role's IAM policy is scoped to resources with the `lfg-<stage>-` prefix, and cost reports and clean-up scripts rely on it too. A function with another name falls outside those controls, and a function without the stage in its name could collide with, or overwrite, its twin in the other stage.

Compliant (spec name `nightly-report`):

```yaml
FunctionName: !Sub "lfg-${Stage}-nightly-report"
```

Non-compliant:

```yaml
FunctionName: nightly-report
```

**CWE:** none.

### LFG-SPEC-001

**Rule:** Every IAM action in the template is declared in the spec.

**Why it matters:** The spec is where a person states, with a reason, what the function may do. If the template could hold extra actions, the review of the spec would be meaningless: the deployed function would hold power nobody approved. Checking the template against the spec means an addition has to be visible in the spec first.

Compliant (spec and template agree):

```yaml
# spec
permissions:
  - actions: ["sqs:SendMessage"]
    resources: ["arn:aws:sqs:eu-west-1:<account-id>:lfg-dev-alerts"]
    reason: Sends an alert when the report fails.
```

Non-compliant: the template also allows `s3:GetObject`, which the spec never lists.

**CWE:** CWE-269 (improper privilege management).

### LFG-SPEC-002

**Rule:** The runtime, architecture, timeout, memory and trigger in the template match the spec.

**Why it matters:** These settings affect cost, speed, exposure and which language patches apply. If the template differs from the spec, the people who approved the spec believe in a function that is not the one running. A longer timeout than approved can also mean a runaway function costs more than expected.

Compliant: spec `timeout: 30` and template `Timeout: 30`.

Non-compliant: spec `timeout: 30` and template `Timeout: 300`.

**CWE:** none.

### LFG-TRG-001

**Rule:** The trigger type is enabled in this release.

**Why it matters:** The spec format knows about more trigger types than the checker can currently judge safely. A trigger such as an HTTP endpoint exposes the function to callers, and accepting it without rules to check it would be a gap. Refusing what is not yet understood keeps the checker honest. Enabled types are `schedule` and `eventbridge`.

Compliant:

```yaml
trigger:
  type: schedule
  expression: cron(0 2 * * ? *)
```

Non-compliant:

```yaml
trigger:
  type: http
  method: GET
  path: /report
  auth: none
```

**CWE:** none.

### LFG-RA-001

**Rule:** A risk acceptance names a known rule of class `accept` and has not expired.

**Why it matters:** A waiver is only as good as its limits. An acceptance that names a typo, or a rule that can never be waived, would look like approval while doing nothing, or worse, be read as approval of something forbidden. An acceptance with no expiry silently becomes permanent, so the original reasoning is never revisited.

Compliant:

```yaml
risk_acceptances:
  - rule_id: LFG-RUN-002
    justification: The export needs two minutes because of the file size.
    accepted_by: platform-team
    expires: 2027-03-31
```

Non-compliant: the same entry with `rule_id: LFG-IAM-001` (a `deny` rule) or with an `expires` date in the past.

**CWE:** none.

## IAM rules

### LFG-IAM-001

**Rule:** No statement allows every action: not `*`, not any action made only of `*` and `?`, and not an action whose service part contains a wildcard (`*:*`, `i?m:PassRole`).

**Why it matters:** The action `*` means every API call in AWS, and a wildcard in the service part, such as `*:*` or `?am:PassRole`, may match actions of other services or be rejected by IAM; either way the checker refuses it. These are the same kind of risk, so they are reported here and not under the narrower wildcard rule. If the function is compromised, for example through a flaw in its code or a malicious dependency, the attacker inherits whatever the function may do. With `*` that is everything the resource list reaches, including deleting data or creating new access for themselves.

Compliant:

```yaml
Policies:
  - Statement:
      - Effect: Allow
        Action: sqs:SendMessage
        Resource: !GetAtt AlertQueue.Arn
```

Non-compliant:

```yaml
Policies:
  - Statement:
      - Effect: Allow
        Action: "*"
        Resource: !GetAtt AlertQueue.Arn
```

**CWE:** CWE-732 (incorrect permission assignment for critical resource). **OWASP Serverless Top 10:** over-privileged function permissions and roles.

### LFG-IAM-002

**Rule:** No statement uses `NotAction` or `NotResource`.

**Why it matters:** `NotAction` with `Allow` means "everything except these actions", and `NotResource` means "every resource except these". Both grant a huge, open-ended set, and they grow automatically as AWS adds new services. A reader cannot list what is permitted. Explicit lists can be reviewed.

Compliant:

```yaml
- Effect: Allow
  Action: sns:Publish
  Resource: !Ref AlertTopic
```

Non-compliant:

```yaml
- Effect: Allow
  NotAction: iam:*
  Resource: "*"
```

**CWE:** CWE-732. **OWASP Serverless Top 10:** over-privileged function permissions and roles.

### LFG-IAM-003

**Rule:** Permissions are inline statements only: no managed policies and no SAM policy templates.

**Why it matters:** A managed policy or SAM policy template hides its contents behind a name. The meaning can be broader than the name suggests, and an AWS-managed policy can change without the template changing. Inline statements put every permission the template author wrote in front of the reviewer, where the check against the spec can see them. One exception is expected: SAM automatically attaches the AWS-managed policy `AWSLambdaBasicExecutionRole` to every role it generates, which is why the function can write logs without a statement for it. The checker inspects what the author wrote under `Policies`, and the permissions boundary (LFG-IAM-004) caps everything the role can do, including that implicit policy.

Compliant:

```yaml
Policies:
  - Statement:
      - Effect: Allow
        Action: sqs:SendMessage
        Resource: !GetAtt AlertQueue.Arn
```

Non-compliant:

```yaml
Policies:
  - AmazonS3FullAccess
  - SQSSendMessagePolicy:
      QueueName: !GetAtt AlertQueue.QueueName
```

**CWE:** CWE-269.

### LFG-IAM-004

**Rule:** Every role SAM creates carries the `lfg-function-boundary` permissions boundary, written exactly as `!Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary"`, and no external `Role` or schedule `RoleArn` is supplied.

**Why it matters:** A permissions boundary is a ceiling: whatever the role's own policies say, it can never do more than the boundary allows. It protects against mistakes that slip past every other check. Supplying your own `Role` (or a `RoleArn` on a schedule) would bypass the boundary, since SAM would then not create or constrain the role. The value must match exactly, in the function and in every schedule event: a name that merely contains the boundary's name, or a conditional that only sometimes yields it, would let a different policy be used.

Compliant:

```yaml
Properties:
  PermissionsBoundary: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary"
```

Non-compliant:

```yaml
Properties:
  Role: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/some-existing-role"
```

**CWE:** CWE-269. **OWASP Serverless Top 10:** over-privileged function permissions and roles.

### LFG-IAM-005

**Rule:** A resource that names everything (`"*"`, `"arn:aws:s3:::*"`, `"arn:aws:logs:*:*:*"`, or an `Fn::Sub` that reads as one) is used only with actions that cannot be scoped to a resource.

**Why it matters:** `Resource: "*"` makes an action apply to every resource of that kind in the account, and so does an ARN whose resource part is only wildcards. The checker reads the text of the resource (substitutions such as `${AWS::AccountId}` count as ordinary text) and treats it as unscoped when nothing specific is left. Only a closed list of forms is accepted in a `Resource`: a plain string without whitespace; a `Ref` or `Fn::GetAtt` to a resource declared in the same template; and a string-form `Fn::Sub` whose variables are `AWS::Partition`, `AWS::Region`, `AWS::AccountId`, `Stage` or such a resource. Everything else is reported under LFG-IAM-007, because a template parameter, a nested intrinsic, `Fn::Join` or the list form of `Fn::Sub` can carry a `*` in at deploy time, after the checker has read the file; only references to resources declared in the same template are certain to name one resource. The one parameter-like value allowed is `${Stage}` in an `Fn::Sub`, which is safe because LFG-TPL-004 pins the `Stage` parameter to `dev` or `prod`. The checker can tell that a resource is unscoped, but it cannot judge whether a scoped ARN, such as every role in an account, is narrow enough; that judgement belongs to the reviewers. For most actions, naming the exact resource limits the damage of a mistake or compromise to that one thing. A few actions have no resource to name, so a star is the only option for them; the catalogue lists those. Anything else with a star needs a recorded acceptance.

Compliant:

```yaml
- Effect: Allow
  Action: xray:PutTraceSegments
  Resource: "*"
- Effect: Allow
  Action: sqs:SendMessage
  Resource: !GetAtt AlertQueue.Arn
```

Non-compliant:

```yaml
- Effect: Allow
  Action: sqs:SendMessage
  Resource: "*"
```

**CWE:** CWE-732. **OWASP Serverless Top 10:** over-privileged function permissions and roles.

### LFG-IAM-006

**Rule:** Actions that change security controls need a recorded acceptance.

**Why it matters:** IAM treats `?` as any single character, so `iam:Pass?ole` is `iam:PassRole` in disguise; the checker catches wildcard actions that overlap a listed action as well as the exact names. Some actions let a function change who may do what, or switch off the evidence of what happened: editing IAM policies, passing roles, changing bucket policies, stopping audit trails. A function holding these can be used to give an attacker lasting access or to hide their tracks. They are sometimes necessary, but never casually, so a named person must accept the risk, with an expiry.

Compliant: a function that only reads from a queue, or a function using `iam:PassRole` with this in its spec:

```yaml
risk_acceptances:
  - rule_id: LFG-IAM-006
    justification: Starts a job that must run under a named role.
    accepted_by: platform-team
    expires: 2027-03-31
```

Non-compliant: the same `iam:PassRole` statement with no acceptance.

**CWE:** CWE-269.

### LFG-IAM-007

**Rule:** Every statement is `Effect: Allow` with explicit `Action` and `Resource`, written as `<service>:<name>`, and with no keys other than `Sid`, `Effect`, `Action`, `Resource` and `Condition`.

**Why it matters:** A statement missing `Resource` or `Action`, or using `Deny`, makes the policy hard to reason about and hard to compare with the spec. Keys such as `Principal` have no place in an identity policy, and an action that is not written as `<service>:<name>` cannot be compared with the spec. The checker compares what the template allows with what the spec declares; that comparison only works if every statement says plainly what it allows, on what.

Compliant:

```yaml
- Effect: Allow
  Action: sns:Publish
  Resource: !Ref AlertTopic
```

Non-compliant:

```yaml
- Effect: Deny
  Action: s3:DeleteObject
```

**CWE:** CWE-732.

### LFG-IAM-008

**Rule:** A wildcard (`*` or `?`) inside an action name needs a recorded acceptance.

**Why it matters:** An action such as `s3:Get*` allows every present and future action that starts with `Get`. AWS adds actions over time, so the permission can quietly grow after the review. Naming each action keeps the permission fixed at what was approved.

Compliant:

```yaml
Action:
  - s3:GetObject
  - s3:ListBucket
```

Non-compliant (without an acceptance):

```yaml
Action: s3:Get*
```

**CWE:** CWE-732. **OWASP Serverless Top 10:** over-privileged function permissions and roles.

## Secrets rules

### LFG-SEC-001

**Rule:** No secret values in environment variables.

**Why it matters:** Lambda encrypts environment variables at rest, but the value is still exposed in clear text in the template, in the repository history, in console and API output to anyone who can call `lambda:GetFunctionConfiguration`, and in the function's runtime environment. A secret store adds what an environment variable lacks: access control on each secret and an audit trail of who read it. Pass only a reference, such as a parameter name or secret ARN, and let the function fetch the value at run time with permission. Names containing words like `password`, `token` or `secret` are treated as suspect unless they end in `_ARN`, `_NAME`, `_PARAM` or `_ID`.

Compliant:

```yaml
Environment:
  Variables:
    DB_PASSWORD_PARAM: /lfg/dev/report/db-password
```

Non-compliant:

```yaml
Environment:
  Variables:
    DB_PASSWORD: correct-horse-battery-staple
```

**CWE:** CWE-526 (cleartext storage of sensitive information in an environment variable). **OWASP Serverless Top 10:** insecure application secrets storage.

### LFG-SEC-002

**Rule:** No hard-coded secrets in source.

**Why it matters:** A secret written into code is copied into every clone, build, backup and log of that code, and stays in version control history even after it is deleted. Anyone who sees the code gains the access. A scanner looks for credential-shaped strings in the source so a human does not have to.

Compliant:

```python
import os
import boto3

name = os.environ["API_KEY_PARAM"]
value = boto3.client("ssm").get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
```

Non-compliant:

```python
API_KEY = "sk_live_0123456789abcdef"
```

**CWE:** CWE-798 (use of hard-coded credentials). **OWASP Serverless Top 10:** insecure application secrets storage.

## Runtime rules

### LFG-RUN-001

**Rule:** The runtime is on the allowed list.

**Why it matters:** Language runtimes stop receiving security fixes when they reach the end of their support. A function on an old runtime carries known, unpatched weaknesses, and AWS will eventually block updates to it. The allowed runtimes are `python3.13` and `python3.14`.

Compliant:

```yaml
Runtime: python3.13
```

Non-compliant:

```yaml
Runtime: python3.8
```

**CWE:** CWE-1104 (use of unmaintained third-party components).

### LFG-RUN-002

**Rule:** A timeout above 60 seconds needs a recorded acceptance.

**Why it matters:** The timeout is the limit on how long one run may last. A long timeout lets a stuck or abused function keep running, and keep costing money, for a long time. Most event-driven work finishes quickly, so a long limit should be a deliberate, recorded choice.

Compliant:

```yaml
Timeout: 30
```

Non-compliant (without an acceptance):

```yaml
Timeout: 300
```

**CWE:** CWE-400 (uncontrolled resource consumption). **OWASP Serverless Top 10:** denial of service and financial resource exhaustion.

## Reliability and logging rules

### LFG-LOG-001

**Rule:** A log group with the spec's retention is declared and used.

**Why it matters:** If the template does not declare the log group, Lambda creates one on first run, with no expiry. Logs then grow forever, and nobody decided how long they should be kept. The log group is also the record of what the function did, which is needed to investigate a problem. Declaring it lets the spec set the retention, and `LoggingConfig` makes the function write there.

Compliant:

```yaml
LogGroup:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: !Sub "/aws/lambda/lfg-${Stage}-nightly-report"
    RetentionInDays: 30
Function:
  Type: AWS::Serverless::Function
  Properties:
    LoggingConfig:
      LogGroup: !Ref LogGroup
```

Non-compliant: no `LogGroup` resource, or one without `RetentionInDays`.

**CWE:** CWE-778 (insufficient logging). **OWASP Serverless Top 10:** inadequate function monitoring and logging.

### LFG-REL-001

**Rule:** Asynchronous triggers have a failure destination.

**Why it matters:** When a function invoked asynchronously, such as by a schedule or an event, fails after its retries, the event is dropped unless something catches it. The work is lost and nobody is told. A queue or topic as a failure destination keeps the failed event for inspection and replay. The destination must be an SQS queue or SNS topic declared in the same template, referred to by `Ref` or `Fn::GetAtt`, because SAM adds send permissions for it to the function's role outside `Policies`, where the spec comparison cannot see them; an external ARN would be an unreviewed outbound channel. `OnSuccess` destinations are not allowed.

Compliant:

```yaml
EventInvokeConfig:
  DestinationConfig:
    OnFailure:
      Type: SQS
      Destination: !GetAtt FailureQueue.Arn
```

Non-compliant: a scheduled function with no `EventInvokeConfig`.

**CWE:** CWE-755 (improper handling of exceptional conditions).

## Dependency and network rules

### LFG-DEP-001

**Rule:** Dependencies are pinned to exact versions with hashes.

**Why it matters:** A loose requirement such as `requests>=2` installs whatever is newest at build time. If an attacker publishes a malicious release, or takes over a package, the next build pulls it into your function. Exact versions with hashes mean the build installs only the files that were reviewed, and refuses anything altered.

Compliant `requirements.txt`:

```text
requests==2.32.3 \
    --hash=sha256:<64-hex-digit-hash>
```

Non-compliant `requirements.txt`:

```text
requests>=2
```

**CWE:** CWE-1357 (reliance on uncontrolled component). **OWASP Serverless Top 10:** insecure third-party dependencies.

### LFG-NET-001

**Rule:** A function URL without IAM authentication needs a recorded acceptance.

**Why it matters:** A function URL is a public web address for the function. With `AuthType: NONE`, anyone on the internet can call it, as often as they like, and each call costs money and runs your code. IAM authentication restricts calls to signed requests from permitted identities. A public function is sometimes intended, so it can be accepted, but the decision must be written down.

Compliant:

```yaml
FunctionUrlConfig:
  AuthType: AWS_IAM
```

Non-compliant (without an acceptance):

```yaml
FunctionUrlConfig:
  AuthType: NONE
```

**CWE:** CWE-306 (missing authentication for critical function). **OWASP Serverless Top 10:** broken authentication.

## Code rules

### LFG-COD-001

**Rule:** The handler validates the event before using it.

**Why it matters:** The event is input from outside the function, and anyone who can cause an event can shape its contents. Using a field without checking it can lead to crashes, wrong behaviour or injection into whatever the value is passed to. Checking the shape and values first means bad input fails early and safely. A reviewer checks this because the right validation depends on the function.

Compliant:

```python
def handler(event, context):
    report_id = event.get("report_id")
    if not isinstance(report_id, str) or not report_id.isalnum():
        raise ValueError("invalid report_id")
```

Non-compliant:

```python
def handler(event, context):
    run(event["report_id"])
```

**CWE:** CWE-20 (improper input validation). **OWASP Serverless Top 10:** injection.

### LFG-COD-002

**Rule:** Logs do not contain whole events, secrets or personal data.

**Why it matters:** Logs are widely readable, kept for a long time and copied to other systems. An event may carry a password, a token or a person's details, and logging all of it spreads that data to everyone who can read the logs. Log what is needed to follow what happened, such as identifiers and outcomes.

Compliant:

```python
logger.info("report started", extra={"report_id": report_id})
```

Non-compliant:

```python
logger.info("received %s", event)
```

**CWE:** CWE-532 (insertion of sensitive information into a log file).

### LFG-COD-003

**Rule:** No dynamic code execution, shell invocation or unsafe deserialisation.

**Why it matters:** Functions such as `eval`, `exec`, a shell call built from a string, or `pickle.loads` on data you did not produce will run instructions hidden inside the input. An attacker who controls any part of that input then controls the function, and with it every permission the function holds. Use plain data formats such as JSON and call libraries directly instead of through a shell.

Compliant:

```python
import json

data = json.loads(body)
```

Non-compliant:

```python
import pickle

data = pickle.loads(body)
```

**CWE:** CWE-94 (improper control of generation of code). **OWASP Serverless Top 10:** injection.
