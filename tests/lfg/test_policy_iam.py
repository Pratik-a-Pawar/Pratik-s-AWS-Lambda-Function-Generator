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


def _res1(value):
    return lambda spec, template: _statements(template)[1].update(Resource=value)


def _event_property(name, value):
    def mutate(spec, template):
        _props(template)["Events"]["Daily"]["Properties"][name] = value

    return mutate


def _param_star(spec, template):
    template["Parameters"]["Star"] = {"Type": "String", "Default": "*"}
    _statements(template)[1]["Resource"] = {"Ref": "Star"}


BOUNDARY = "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary"
IAM2 = {"LFG-IAM-006", "LFG-IAM-008"}


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
    # R1: "?" is a wildcard.
    ("question_mark_pass_role_middle", _add("iam:Pass?ole"), IAM2),
    ("question_mark_pass_role_end", _add("iam:PassRol?"), IAM2),
    ("question_mark_bucket_policy", _add("s3:PutBucket?olicy"), IAM2),
    ("question_mark_plain", _add("s3:Get?bject"), {"LFG-IAM-008"}),
    # R2: action form.
    ("action_double_star", _stmt0(Action="**"), {"LFG-IAM-001"}),
    ("action_star_question", _stmt0(Action="*?"), {"LFG-IAM-001"}),
    ("action_star_colon_star", _stmt0(Action="*:*"), {"LFG-IAM-001"}),
    ("action_service_question", _stmt0(Action="i?m:PassRole"), {"LFG-IAM-001"}),
    ("action_service_leading_question", _stmt0(Action="?am:PassRole"), {"LFG-IAM-001"}),
    (
        "action_empty_string_in_list",
        _stmt0(Action=["iam:GetCredentialReport", ""]),
        {"LFG-IAM-007"},
    ),
    ("action_leading_space", _stmt0(Action=" iam:PassRole"), {"LFG-IAM-007"}),
    ("action_no_service", _stmt0(Action="ListUsers"), {"LFG-IAM-007"}),
    ("action_empty_name", _stmt0(Action="iam:"), {"LFG-IAM-007"}),
    # R3: resources that mean "everything".
    ("res_sub_star", _res1({"Fn::Sub": "*"}), {"LFG-IAM-005"}),
    ("res_join_star", _res1({"Fn::Join": ["", ["*"]]}), {"LFG-IAM-007"}),
    ("res_arn_star", _res1("arn:*"), {"LFG-IAM-005"}),
    ("res_star_slash_star", _res1("*/*"), {"LFG-IAM-005"}),
    ("res_s3_all", _res1("arn:aws:s3:::*"), {"LFG-IAM-005"}),
    ("res_logs_all", _res1("arn:aws:logs:*:*:*"), {"LFG-IAM-005"}),
    (
        "res_sub_all_in_account",
        _res1({"Fn::Sub": "arn:${AWS::Partition}:sns:${AWS::Region}:${AWS::AccountId}:*"}),
        {"LFG-IAM-005"},
    ),
    ("res_bucket_objects_scoped", _res1("arn:aws:s3:::my-bucket/*"), set()),
    (
        "res_sub_named_scoped",
        _res1({"Fn::Sub": "arn:${AWS::Partition}:sns:${AWS::Region}:${AWS::AccountId}:lfg-${Stage}-alerts"}),
        set(),
    ),
    ("res_getatt_scoped", _res1({"Fn::GetAtt": ["AlertTopic", "TopicArn"]}), set()),
    ("res_join_scoped", _res1({"Fn::Join": [":", ["arn", "aws", "sns", "eu-west-1", "x", "topic"]]}), {"LFG-IAM-007"}),
    ("res_sub_list_form", _res1({"Fn::Sub": ["arn:aws:sns:::${T}", {"T": "x"}]}), {"LFG-IAM-007"}),
    ("res_fn_if", _res1({"Fn::If": ["C", "a", "b"]}), {"LFG-IAM-007"}),
    ("res_ref_extra_key", _res1({"Ref": "A", "Extra": "b"}), {"LFG-IAM-007"}),
    ("res_import_value", _res1({"Fn::ImportValue": "x"}), {"LFG-IAM-007"}),
    ("res_ref_not_string", _res1({"Ref": ["A"]}), {"LFG-IAM-007"}),
    ("res_sub_not_string", _res1({"Fn::Sub": 3}), {"LFG-IAM-007"}),
    ("res_join_bad_shape", _res1({"Fn::Join": "x"}), {"LFG-IAM-007"}),
    # R4: the boundary must be exact.
    (
        "boundary_suffix_evil",
        _property("PermissionsBoundary", {"Fn::Sub": BOUNDARY + "-evil"}),
        {"LFG-IAM-004"},
    ),
    (
        "boundary_in_fn_if",
        _property(
            "PermissionsBoundary",
            {"Fn::If": ["C", "arn:x:policy/Admin", {"Fn::Sub": BOUNDARY}]},
        ),
        {"LFG-IAM-004"},
    ),
    (
        "boundary_ref_with_junk",
        _property("PermissionsBoundary", {"Ref": "x", "Junk": "policy/lfg-function-boundary"}),
        {"LFG-IAM-004"},
    ),
    ("boundary_plain_string", _property("PermissionsBoundary", BOUNDARY), {"LFG-IAM-004"}),
    (
        "schedule_boundary_inexact",
        _event_property("PermissionsBoundary", {"Fn::Sub": BOUNDARY + "-evil"}),
        {"LFG-IAM-004"},
    ),
    # R5: ScheduleV2 RoleArn.
    (
        "schedule_role_arn",
        _event_property("RoleArn", {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/x"}),
        {"LFG-IAM-004"},
    ),
    # R7: statement keys.
    ("statement_principal", _stmt0(Principal="*"), {"LFG-IAM-007"}),
    ("statement_not_principal", _stmt0(NotPrincipal="*"), {"LFG-IAM-007"}),
    (
        "statement_sid_and_condition",
        _stmt0(Sid="Report", Condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}),
        set(),
    ),
    # F1: anchored patterns must not accept a trailing or leading newline.
    ("action_trailing_newline", _add("iam:PassRole\n"), {"LFG-IAM-007"}),
    ("action_star_trailing_newline", _add("iam:*\n"), {"LFG-IAM-007"}),
    ("action_leading_newline", _add("\niam:PassRole"), {"LFG-IAM-007"}),
    # F2: resource forms are a closed list.
    ("res_sub_list_star", _res1({"Fn::Sub": ["${X}", {"X": "*"}]}), {"LFG-IAM-007"}),
    ("res_sub_list_bucket_star", _res1({"Fn::Sub": ["arn:aws:s3:::${B}", {"B": "*"}]}), {"LFG-IAM-007"}),
    ("res_join_nested_sub", _res1({"Fn::Join": ["", [{"Fn::Sub": "*"}]]}), {"LFG-IAM-007"}),
    ("res_ref_parameter", _res1({"Ref": "Stage"}), {"LFG-IAM-007"}),
    ("res_ref_pseudo_parameter", _res1({"Ref": "AWS::AccountId"}), {"LFG-IAM-007"}),
    ("res_ref_unknown", _res1({"Ref": "NoSuchResource"}), {"LFG-IAM-007"}),
    ("res_ref_parameter_default_star", _param_star, {"LFG-IAM-007", "LFG-TPL-004"}),
    ("res_getatt_star_string", _res1({"Fn::GetAtt": "*"}), {"LFG-IAM-007"}),
    ("res_getatt_unknown", _res1({"Fn::GetAtt": ["NoSuchResource", "Arn"]}), {"LFG-IAM-007"}),
    ("res_getatt_list_not_strings", _res1({"Fn::GetAtt": [["x"], "Arn"]}), {"LFG-IAM-007"}),
    (
        "res_sub_unknown_variable",
        _res1({"Fn::Sub": "arn:${AWS::Partition}:sns:${AWS::Region}:${AWS::AccountId}:${TopicName}"}),
        {"LFG-IAM-007"},
    ),
    ("res_sub_stack_name", _res1({"Fn::Sub": "${AWS::StackName}"}), {"LFG-IAM-007"}),
    ("res_sub_literal_escape", _res1({"Fn::Sub": "arn:aws:sns:::${!X}"}), {"LFG-IAM-007"}),
    ("res_string_leading_space", _res1(" *"), {"LFG-IAM-007"}),
    ("res_string_inner_space", _res1("arn:aws:s3:::my bucket"), {"LFG-IAM-007"}),
    ("res_sub_with_space", _res1({"Fn::Sub": "arn:aws:s3:::my bucket"}), {"LFG-IAM-007"}),
    ("res_arn_upper_case", _res1("ARN:*"), {"LFG-IAM-005"}),
    ("res_ref_resource_ok", _res1({"Ref": "AlertTopic"}), set()),
    ("res_getatt_list_ok", _res1({"Fn::GetAtt": ["FailureQueue", "Arn"]}), set()),
    ("res_getatt_string_ok", _res1({"Fn::GetAtt": "FailureQueue.Arn"}), set()),
    ("res_sub_resource_ok", _res1({"Fn::Sub": "${AlertTopic}"}), set()),
    ("res_sub_attribute_ok", _res1({"Fn::Sub": "${FailureQueue.Arn}"}), set()),
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
