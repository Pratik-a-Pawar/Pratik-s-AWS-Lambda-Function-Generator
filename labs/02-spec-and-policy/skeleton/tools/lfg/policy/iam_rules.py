"""IAM rules: inline statements only, boundary present, no wildcards or unscoped access.

Lab 02, part C. Rules served: LFG-IAM-001 to LFG-IAM-008 and LFG-SPEC-001. The brief is
labs/02-spec-and-policy/README.md; the checks are in tests/lfg/test_policy_iam.py.

Reuse get_function and is_resource_reference from lfg.policy.template_rules.
"""

from lfg.policy import Violation
from lfg.rules import Catalogue

BOUNDARY = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary"}
SCHEDULE_EVENT_TYPE = "ScheduleV2"
STATEMENT_KEYS = ("Sid", "Effect", "Action", "Resource", "Condition")
PSEUDO_PARAMETERS = ("AWS::Partition", "AWS::Region", "AWS::AccountId")


def check_iam(spec: dict, template: dict, catalogue: Catalogue) -> list[Violation]:
    """Check the function's IAM settings and its inline policy statements.

    Rules served: LFG-IAM-001 to LFG-IAM-008 and LFG-SPEC-001. What each rule refuses, and
    why, is in standards/secure-lambda-standard.md. The exact cases, each with the rule IDs
    it must produce, are the rows of tests/lfg/test_policy_iam.py. Together those two are the
    specification; this docstring only fixes the interface.

    Return the raw violations, none of them marked accepted: check() applies the risk
    acceptances afterwards. Return [] when get_function finds no function.

    Locations. <base> is "template.yaml:Resources.<id>.Properties", <id> being the function's
    logical ID.
    - A setting on the function: <base>.<Property>, for example <base>.PermissionsBoundary.
    - A setting on an event: <base>.Events.<event>.Properties.<Property>.
    - Policies as a whole: <base>.Policies. One item of it: <base>.Policies[<i>].
    - A statement: <base>.Policies[<i>].Statement[<j>] when Statement is a list, otherwise
      <base>.Policies[<i>].Statement. Every problem found in a statement is reported at the
      statement, and a statement reports each rule at most once.

    Fail closed. Policies, statements, actions, resources and the spec's permissions can each
    be any YAML value: a mapping, a list, a string, a number, null, or missing. None of them
    may raise an exception, and none may pass unless it is a shape the standard allows.
    """
    raise NotImplementedError("Lab 02, part C: check the IAM rules")
