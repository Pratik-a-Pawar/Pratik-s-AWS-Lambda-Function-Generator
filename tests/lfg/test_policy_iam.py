import copy
from datetime import date

import pytest
from conftest import rule_ids
from lfg.policy import check

ARN = "arn:aws:s3:::example-bucket"


def _props(template):
    return template["Resources"]["Function"]["Properties"]


def _statements(template):
    return _props(template)["Policies"][0]["Statement"]


def _declare(spec, *actions):
    spec["permissions"].append({"actions": list(actions), "resources": [ARN], "reason": "Test."})


def _add(action, resource=ARN, declared=True):
    """Add a statement to the template, and declare its actions in the spec."""
    actions = action if isinstance(action, list) else [action]

    def mutate(spec, template):
        _statements(template).append({"Effect": "Allow", "Action": action, "Resource": resource})
        if declared:
            _declare(spec, *actions)

    return mutate


def _stmt0(**changes):
    def mutate(spec, template):
        statement = _statements(template)[0]
        for key, value in changes.items():
            if value is _DELETE:
                del statement[key]
            else:
                statement[key] = value

    return mutate


_DELETE = object()


def _swap_key(old, new, value):
    def mutate(spec, template):
        statement = _statements(template)[0]
        del statement[old]
        statement[new] = value

    return mutate


def _policies(value):
    def mutate(spec, template):
        _props(template)["Policies"] = value

    return mutate


def _statement_value(value):
    def mutate(spec, template):
        _props(template)["Policies"][0]["Statement"] = value

    return mutate


def _property(name, value):
    def mutate(spec, template):
        _props(template)[name] = value

    return mutate


def _del_property(name):
    def mutate(spec, template):
        del _props(template)[name]

    return mutate


def _schedule_no_boundary(spec, template):
    del _props(template)["Events"]["Daily"]["Properties"]["PermissionsBoundary"]


def _schedule_properties(value):
    def mutate(spec, template):
        _props(template)["Events"]["Daily"]["Properties"] = value

    return mutate


def _single_statement(spec, template):
    _props(template)["Policies"][0]["Statement"] = _statements(template)[1]
    spec["permissions"] = spec["permissions"][1:]


def _no_policies(spec, template):
    del _props(template)["Policies"]
    spec["permissions"] = []


def _declared_case(spec, template):
    spec["permissions"][1]["actions"] = ["SNS:publish"]


def _case_variant(spec, template):
    _add("EC2:revokesecuritygroupingress")(spec, template)


def _spec_permissions(value):
    def mutate(spec, template):
        spec["permissions"] = value

    return mutate


def _spec_actions(value):
    def mutate(spec, template):
        spec["permissions"][1]["actions"] = value

    return mutate


def _spec_extra_entry(entry):
    def mutate(spec, template):
        spec["permissions"].insert(0, entry)

    return mutate


def _rename_sns_to_case(spec, template):
    _statements(template)[1]["Action"] = "SNS:PUBLISH"


MUTATIONS = [
    ("action_star", _stmt0(Action="*"), {"LFG-IAM-001"}),
    (
        "action_star_in_list",
        _stmt0(Action=["iam:GetCredentialReport", "*"]),
        {"LFG-IAM-001"},
    ),
    ("not_action", _swap_key("Action", "NotAction", ["iam:GetCredentialReport"]), {"LFG-IAM-002"}),
    ("not_resource", _swap_key("Resource", "NotResource", "*"), {"LFG-IAM-002"}),
    ("managed_policy_name", _policies(["AdministratorAccess"]), {"LFG-IAM-003"}),
    (
        "managed_policy_arn",
        _policies(["arn:aws:iam::aws:policy/ReadOnlyAccess"]),
        {"LFG-IAM-003"},
    ),
    ("policies_is_string", _policies("AWSLambdaBasicExecutionRole"), {"LFG-IAM-003"}),
    (
        "sam_policy_template",
        _policies([{"S3ReadPolicy": {"BucketName": "b"}}]),
        {"LFG-IAM-003"},
    ),
    ("no_boundary", _del_property("PermissionsBoundary"), {"LFG-IAM-004"}),
    (
        "wrong_boundary",
        _property("PermissionsBoundary", "arn:aws:iam::aws:policy/PowerUserAccess"),
        {"LFG-IAM-004"},
    ),
    (
        "external_role",
        _property("Role", {"Fn::GetAtt": ["Other", "Arn"]}),
        {"LFG-IAM-004"},
    ),
    ("schedule_no_boundary", _schedule_no_boundary, {"LFG-IAM-004"}),
    (
        "star_resource_scopable",
        lambda spec, template: _statements(template)[1].update(Resource="*"),
        {"LFG-IAM-005"},
    ),
    (
        "star_resource_in_list",
        lambda spec, template: _statements(template)[1].update(Resource=["*"]),
        {"LFG-IAM-005"},
    ),
    ("star_resource_wildcard_only", lambda spec, template: None, set()),
    ("describe_wildcard_only", _add("ec2:DescribeSecurityGroups", "*"), set()),
    ("sensitive_action", _add("ec2:RevokeSecurityGroupIngress"), {"LFG-IAM-006"}),
    ("sensitive_action_case", _case_variant, {"LFG-IAM-006"}),
    ("pass_role", _add("iam:PassRole"), {"LFG-IAM-006"}),
    ("effect_deny", _stmt0(Effect="Deny"), {"LFG-IAM-007"}),
    ("effect_missing", _stmt0(Effect=_DELETE), {"LFG-IAM-007"}),
    ("resource_missing", _stmt0(Resource=_DELETE), {"LFG-IAM-007"}),
    ("statement_not_mapping", _statement_value(["oops"]), {"LFG-IAM-007"}),
    ("statement_is_mapping", _single_statement, set()),
    ("action_wildcard_suffix", _add("s3:Get*"), {"LFG-IAM-008"}),
    ("service_star", _add("s3:*"), {"LFG-IAM-006", "LFG-IAM-008"}),
    ("wildcard_covers_sensitive", _add("iam:Pass*"), {"LFG-IAM-006", "LFG-IAM-008"}),
    ("undeclared_action", _add("s3:GetObject", declared=False), {"LFG-SPEC-001"}),
    ("declared_case_differs", _declared_case, set()),
    ("no_policies", _no_policies, set()),
    # Unexpected shapes: every one is a violation, never an exception.
    ("policies_is_mapping", _policies({"Statement": []}), {"LFG-IAM-003"}),
    ("policies_is_null", _policies(None), {"LFG-IAM-003"}),
    ("policies_item_is_number", _policies([7]), {"LFG-IAM-003"}),
    ("policies_item_is_list", _policies([[{"Statement": []}]]), {"LFG-IAM-003"}),
    ("policies_item_no_statement", _policies([{"Version": "2012-10-17"}]), {"LFG-IAM-003"}),
    ("statement_is_string", _statement_value("oops"), {"LFG-IAM-007"}),
    ("statement_is_null", _statement_value(None), {"LFG-IAM-007"}),
    ("statement_is_number", _statement_value(3), {"LFG-IAM-007"}),
    ("statement_item_is_list", _statement_value([["a"]]), {"LFG-IAM-007"}),
    ("action_missing", _stmt0(Action=_DELETE), {"LFG-IAM-007"}),
    ("action_is_mapping", _stmt0(Action={"Fn::Sub": "iam:${X}"}), {"LFG-IAM-007"}),
    ("action_is_number", _stmt0(Action=5), {"LFG-IAM-007"}),
    ("action_is_null", _stmt0(Action=None), {"LFG-IAM-007"}),
    ("action_is_empty_list", _stmt0(Action=[]), {"LFG-IAM-007"}),
    (
        "action_list_has_mapping",
        _stmt0(Action=["iam:GetCredentialReport", {"Ref": "X"}]),
        {"LFG-IAM-007"},
    ),
    ("resource_is_number", _stmt0(Resource=4), {"LFG-IAM-007"}),
    ("resource_is_null", _stmt0(Resource=None), {"LFG-IAM-007"}),
    ("resource_is_empty_list", _stmt0(Resource=[]), {"LFG-IAM-007"}),
    ("resource_list_has_number", _stmt0(Resource=["*", 1]), {"LFG-IAM-007"}),
    ("effect_is_list", _stmt0(Effect=["Allow"]), {"LFG-IAM-007"}),
    ("effect_is_mapping", _stmt0(Effect={"Ref": "E"}), {"LFG-IAM-007"}),
    ("effect_wrong_case", _stmt0(Effect="allow"), {"LFG-IAM-007"}),
    (
        "not_action_and_malformed_effect",
        _stmt0(Effect="Deny", NotAction="s3:*"),
        {"LFG-IAM-002"},
    ),
    (
        "resource_intrinsic_ref_is_valid",
        lambda spec, template: _statements(template)[1].update(Resource={"Ref": "AlertTopic"}),
        set(),
    ),
    (
        "resource_intrinsic_sub_is_valid",
        lambda spec, template: _statements(template)[1].update(
            Resource=[{"Fn::Sub": "arn:${AWS::Partition}:sns:*:*:t"}]
        ),
        set(),
    ),
    (
        "intrinsic_resource_is_not_star",
        _stmt0(Resource={"Ref": "AlertTopic"}),
        set(),
    ),
    ("boundary_is_number", _property("PermissionsBoundary", 3), {"LFG-IAM-004"}),
    ("boundary_is_list_without_name", _property("PermissionsBoundary", ["x"]), {"LFG-IAM-004"}),
    (
        "boundary_intrinsic_other_policy",
        _property("PermissionsBoundary", {"Fn::Sub": "arn:aws:iam::1:policy/other"}),
        {"LFG-IAM-004"},
    ),
    ("role_is_string", _property("Role", "arn:aws:iam::1:role/r"), {"LFG-IAM-004"}),
    ("schedule_properties_not_mapping", _schedule_properties(["x"]), {"LFG-IAM-004", "LFG-SPEC-002"}),
    ("template_action_case_upper", _rename_sns_to_case, set()),
    ("spec_permissions_is_string", _spec_permissions("oops"), {"LFG-SPEC-001"}),
    ("spec_permissions_is_mapping", _spec_permissions({"actions": ["sns:Publish"]}), {"LFG-SPEC-001"}),
    ("spec_permissions_is_null", _spec_permissions(None), {"LFG-SPEC-001"}),
    ("spec_permissions_missing", lambda spec, template: spec.pop("permissions"), {"LFG-SPEC-001"}),
    (
        "spec_permissions_entry_not_mapping",
        _spec_permissions(["sns:Publish", 3, None]),
        {"LFG-SPEC-001"},
    ),
    ("spec_actions_is_string", _spec_actions("sns:Publish"), {"LFG-SPEC-001"}),
    ("spec_actions_is_mapping", _spec_actions({"a": "sns:Publish"}), {"LFG-SPEC-001"}),
    ("spec_actions_missing", lambda spec, template: spec["permissions"][1].pop("actions"), {"LFG-SPEC-001"}),
    ("spec_actions_has_mapping_entry", _spec_actions([{"x": 1}, "sns:Publish"]), set()),
    ("spec_actions_only_non_strings", _spec_actions([1, None]), {"LFG-SPEC-001"}),
    (
        "spec_extra_malformed_entry_is_ignored",
        _spec_extra_entry(["not", "a", "mapping"]),
        set(),
    ),
]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [pytest.param(m, e, id=i) for i, m, e in MUTATIONS],
)
def test_iam_rule(good_dir, good_spec, good_template, mutate, expected):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    mutate(spec, template)
    result = check(spec, template, good_dir / "src", date(2026, 11, 16))
    assert rule_ids(result) == expected


def _accept(spec, rule_id):
    spec["risk_acceptances"] = [
        {
            "rule_id": rule_id,
            "justification": "Needed for the test.",
            "accepted_by": "platform-team",
            "expires": "2027-03-31",
        }
    ]


def test_sensitive_action_can_be_accepted(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _add("ec2:RevokeSecurityGroupIngress")(spec, template)
    _accept(spec, "LFG-IAM-006")
    result = check(spec, template, good_dir / "src", date(2026, 11, 16))
    assert rule_ids(result) == set()
    assert {v.rule_id for v in result if v.accepted} == {"LFG-IAM-006"}


def test_action_star_cannot_be_accepted(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _stmt0(Action="*")(spec, template)
    _accept(spec, "LFG-IAM-001")
    result = check(spec, template, good_dir / "src", date(2026, 11, 16))
    assert rule_ids(result) == {"LFG-IAM-001", "LFG-RA-001"}


def test_violation_location_names_the_statement(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _stmt0(Effect="Deny")(spec, template)
    result = check(spec, template, good_dir / "src", date(2026, 11, 16))
    assert [v.location for v in result] == [
        "template.yaml:Resources.Function.Properties.Policies[0].Statement[0]"
    ]


def test_one_violation_per_statement_per_rule(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _add(["s3:Get*", "s3:List*"])(spec, template)
    result = check(spec, template, good_dir / "src", date(2026, 11, 16))
    assert [v.rule_id for v in result] == ["LFG-IAM-008"]
