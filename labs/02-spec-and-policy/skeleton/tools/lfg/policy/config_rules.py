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

    Return [] when get_function finds no function. Below, <base> is
    "template.yaml:Resources.<id>.Properties", <id> being the function's logical ID.

    LFG-SEC-001, environment variables. Messages never contain a variable's value.
    - Template: if the properties have an Environment key, a value that is not a mapping is
      one violation at <base>.Environment. Otherwise each key other than Variables is one
      violation at <base>.Environment.<key>, and Variables, when present, is checked as
      below at <base>.Environment.Variables.
    - Spec: if the spec has an environment key, it is checked as below at
      function.spec.yaml:environment.
    - Checking a set of variables at <loc>: a value that is not a mapping is one violation at
      <loc>. Otherwise each name is one violation at <loc>.<name> when it is not a string,
      when it is "Ref" or starts with "Fn::" (an intrinsic standing in for the variables), or
      when it looks like a secret: catalogue.secret_name_pattern is found anywhere in it,
      and it does not end with one of catalogue.secret_name_safe_suffixes.

    LFG-LOG-001, one violation at most, for the first of these that fails:
    - LoggingConfig is a mapping, else at <base>.LoggingConfig;
    - its LogGroup is a Ref (not Fn::GetAtt) for which is_resource_reference is True, else at
      <base>.LoggingConfig.LogGroup;
    - the resource it names is a mapping of Type LOG_GROUP_TYPE, else at
      <base>.LoggingConfig.LogGroup;
    - that resource's Properties.RetentionInDays and the spec's log_retention_days are both
      integers (a bool is not one) and equal, else at
      template.yaml:Resources.<log group>.Properties.RetentionInDays.

    LFG-REL-001, failure destinations. A destination is valid when it is a mapping whose only
    keys are Type and its target key; Type is exactly a string in DESTINATION_TYPES; when the
    spec's failure_destination is in SPEC_DESTINATIONS, Type in lower case equals it; and the
    target is, for SQS, an Fn::GetAtt of the attribute Arn on a QUEUE_TYPE resource or, for
    SNS, a Ref to a TOPIC_TYPE resource, declared in this template. An invalid destination is
    one violation, for the first problem in that order (shape, keys, Type, agreement with the
    spec, target): at <dest>.<key> for a key that is not allowed, at <dest>.<target key> for
    a wrong or missing target, and at <dest> for the rest.
    - DeadLetterQueue, if present, is a destination with target key TargetArn, and <dest> is
      <base>.DeadLetterQueue.
    - EventInvokeConfig, if present: not a mapping is one violation at <base>.EventInvokeConfig;
      each key not in EVENT_INVOKE_KEYS is one at <base>.EventInvokeConfig.<key>. Its
      DestinationConfig, when present, must be a mapping (else one violation at
      <base>.EventInvokeConfig.DestinationConfig) whose only key is OnFailure (each other key,
      OnSuccess included, is one violation at ...DestinationConfig.<key>). OnFailure, if
      present, is a destination with target key Destination, and <dest> is
      <base>.EventInvokeConfig.DestinationConfig.OnFailure.
    - If the spec's trigger.type is in ASYNC_TRIGGERS: when there is no valid destination and
      no LFG-REL-001 has been reported yet, one violation at <base>; and when the spec's
      failure_destination is not in SPEC_DESTINATIONS, one at
      function.spec.yaml:failure_destination.

    LFG-NET-001: if the properties have a FunctionUrlConfig key, a value that is not a mapping
    is one violation at <base>.FunctionUrlConfig, and an AuthType that is not exactly
    FUNCTION_URL_AUTH is one at <base>.FunctionUrlConfig.AuthType.

    LFG-DEP-001, source_dir / "requirements.txt", every violation located at
    "requirements.txt":
    - a file that does not exist is not a violation, but a symbolic link to nothing is one;
    - a file that cannot be read (a directory, not UTF-8, no permission) is one violation;
      a leading UTF-8 byte order mark is allowed;
    - otherwise each requirement that is not pinned and hashed is one violation. A
      requirement is a line joined with the lines after it while it ends in a backslash, with
      any comment ("#" at the start or after whitespace, to the end of the line) removed;
      blank requirements are skipped. A requirement is pinned and hashed when it is exactly
      one <name>==<version> pin (the name may carry [extras]; the version has no wildcard; no
      "==="), optional environment markers after ";", and one or more
      --hash=sha256:<exactly 64 hex digits> options, with no other options, no "@" and no URL.
    """
    raise NotImplementedError("Lab 02, part D: check the configuration rules")
