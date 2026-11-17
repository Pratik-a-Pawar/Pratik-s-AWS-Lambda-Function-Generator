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

    Return [] when get_function finds no function. Below, <base> is
    "template.yaml:Resources.<id>.Properties", <id> being the function's logical ID.

    LFG-IAM-004, the role and the boundary:
    - a Role key in the function's properties, at <base>.Role;
    - PermissionsBoundary not exactly equal to BOUNDARY, at <base>.PermissionsBoundary;
    - for each event whose Type is SCHEDULE_EVENT_TYPE (a schedule creates a role of its own):
      a RoleArn in its Properties, at <base>.Events.<event>.Properties.RoleArn, and a
      PermissionsBoundary there not exactly equal to BOUNDARY, at
      <base>.Events.<event>.Properties.PermissionsBoundary. Properties that are not a mapping
      count as an empty mapping.

    LFG-IAM-003, the shape of Policies. No Policies key means no statements. Policies that is
    not a list is one violation at <base>.Policies. Each item that is not a mapping with a
    Statement key (a managed policy name or ARN, a SAM policy template, anything else) is one
    violation at <base>.Policies[<i>].

    Statements. A Statement that is a mapping is one statement, located at
    <base>.Policies[<i>].Statement; a list holds one statement per item, located at
    <base>.Policies[<i>].Statement[<j>]; anything else is LFG-IAM-007 at
    <base>.Policies[<i>].Statement. Every statement violation is located at its statement,
    and a statement reports each rule at most once.

    A statement is first checked for form. The first failure below is its only violation:
    1. not a mapping: LFG-IAM-007;
    2. it has NotAction or NotResource: LFG-IAM-002;
    3. it has a key not in STATEMENT_KEYS: LFG-IAM-007;
    4. Effect is not exactly the string "Allow": LFG-IAM-007;
    5. Action is not a string or a non-empty list of strings: LFG-IAM-007;
    6. an action is malformed: LFG-IAM-007 (see the action forms below);
    7. Resource is missing or an empty list, or an entry is not a permitted form: LFG-IAM-007.

    Action forms. IAM treats "*" and "?" as wildcards in an action, and compares actions
    without regard to case. Each action is exactly one of:
    - everything: made only of wildcards, or with a wildcard in its service part
      ("*", "*:*", "?am:PassRole");
    - named: the whole string is <service>:<name>, where <service> is letters, digits and
      hyphens and <name> is letters, digits and wildcards, with nothing else at all before,
      between or after;
    - malformed: anything else, such as "ListUsers", "iam:", " iam:PassRole" or
      "iam:PassRole" followed by a newline.

    Permitted Resource forms, a closed list (ids are the string keys of the template's
    Resources):
    - a string with no whitespace;
    - a Ref or Fn::GetAtt for which is_resource_reference(entry, ids) is True;
    - {"Fn::Sub": <string with no whitespace>} whose every ${...} variable is in
      PSEUDO_PARAMETERS, is "Stage", is a logical ID in ids, or is <logical ID>.<attribute>.
    Everything else (Fn::Join, the list form of Fn::Sub, Fn::If, a Ref to a parameter, any
    other intrinsic or type) is not permitted, whatever it would resolve to.

    A statement that passes the form checks is then checked for content. These can combine:
    - LFG-IAM-001: any action is "everything";
    - LFG-IAM-005: some resource is unscoped and some named action is not matched by any
      pattern in catalogue.wildcard_only_actions. A string or Fn::Sub resource is unscoped
      when, reading each ${...} as one ordinary character, it is made only of "*", "?" and
      "/", or it is an ARN ("arn:" in any case) whose resource part, after the fifth colon, is
      made only of "*", "?", "/" and ":". An ARN with fewer than six parts is unscoped when it
      has a wildcard. A Ref or Fn::GetAtt resource is never unscoped;
    - LFG-IAM-006: some named action is, or could match, an action matched by a pattern in
      catalogue.sensitive_actions ("iam:PassRole", "IAM:passrole", "iam:Pass*" and
      "iam:Pass?ole" all count);
    - LFG-IAM-008: some named action has a wildcard and is not itself one of
      catalogue.wildcard_only_actions;
    - LFG-SPEC-001: some named action is not declared in the spec. The declared actions are
      the strings in the actions list of each mapping in spec["permissions"]; values of any
      other shape declare nothing.
    Every comparison of an action with a pattern or with the spec ignores case.
    """
    raise NotImplementedError("Lab 02, part C: check the IAM rules")
