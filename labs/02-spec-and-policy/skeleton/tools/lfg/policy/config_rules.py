"""Configuration rules: secrets in environment, logging, failure destinations, URLs, dependencies.

Lab 02, part D. Rules served: LFG-SEC-001, LFG-LOG-001, LFG-REL-001, LFG-NET-001 and
LFG-DEP-001. The brief is labs/02-spec-and-policy/README.md; the checks are
tests/lfg/test_policy_config.py and tests/lfg/test_cli_policy_check.py.

Reuse get_function and is_resource_reference from lfg.policy.template_rules.
"""

from pathlib import Path

from lfg.policy import Violation
from lfg.rules import Catalogue

ASYNC_TRIGGERS = ("schedule", "eventbridge")
DESTINATION_TYPES = ("SQS", "SNS")
SPEC_DESTINATIONS = ("sqs", "sns")
QUEUE_TYPE = "AWS::SQS::Queue"
TOPIC_TYPE = "AWS::SNS::Topic"
EVENT_INVOKE_KEYS = ("DestinationConfig", "MaximumRetryAttempts", "MaximumEventAgeInSeconds")
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"
FUNCTION_URL_AUTH = "AWS_IAM"


def check_config(
    spec: dict, template: dict, source_dir: Path, catalogue: Catalogue,
) -> list[Violation]:
    """Check the function's environment, logging, failure handling, URL and dependencies.

    Rules served: LFG-SEC-001, LFG-LOG-001, LFG-REL-001, LFG-NET-001 and LFG-DEP-001. What
    each rule requires, and why, is in standards/secure-lambda-standard.md. The exact cases are
    the rows of tests/lfg/test_policy_config.py, each with the rule IDs it must produce.

    Return the raw violations, none of them marked accepted. Return [] when get_function finds
    no function. Below, <base> is "template.yaml:Resources.<id>.Properties", <id> being the
    function's logical ID.

    LFG-SEC-001 checks the variable names in the template's Environment and in the spec's
    environment, using catalogue.secret_name_pattern and catalogue.secret_name_safe_suffixes.
    A bad name is reported at <base>.Environment.Variables.<name> or
    function.spec.yaml:environment.<name>; a bad shape at the deepest location that exists,
    such as <base>.Environment or function.spec.yaml:environment. Messages never contain a
    variable's value.

    LFG-LOG-001 reports at most one violation: at <base>.LoggingConfig or
    <base>.LoggingConfig.LogGroup when the function does not point at a declared log group,
    and at template.yaml:Resources.<log group>.Properties.RetentionInDays when the retention
    does not match the spec.

    LFG-REL-001 checks the DeadLetterQueue and the EventInvokeConfig failure destination.
    Each invalid destination is one violation, at <dest>.<key> for a key that is not allowed,
    at <dest>.<target key> (TargetArn or Destination) for a wrong or missing target, and at
    <dest> itself for anything else. <dest> is <base>.DeadLetterQueue or
    <base>.EventInvokeConfig.DestinationConfig.OnFailure. A problem in EventInvokeConfig
    outside a destination is reported at the key concerned. When an asynchronous trigger has
    no valid destination and nothing more specific has been reported, the violation is at
    <base>; a spec failure_destination that cannot serve one is at
    function.spec.yaml:failure_destination.

    LFG-NET-001 is reported at <base>.FunctionUrlConfig, or at
    <base>.FunctionUrlConfig.AuthType when that is the problem.

    LFG-DEP-001 reads source_dir / "requirements.txt" and reports every violation at
    "requirements.txt": one per requirement that is not pinned and hashed as the standard
    describes. Having no requirements file at all is not a violation; one that is there but
    cannot be read is.

    Fail closed. Every property and spec field read here can be any YAML value, or missing.
    None may raise an exception, and none may pass unless it is a shape the standard allows.
    """
    raise NotImplementedError("Lab 02, part D: check the configuration rules")
