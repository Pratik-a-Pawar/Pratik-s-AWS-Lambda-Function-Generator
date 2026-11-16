import copy
from datetime import date

import pytest
from conftest import rule_ids
from lfg.policy import check


def _props(template):
    return template["Resources"]["Function"]["Properties"]


def _event(template):
    return _props(template)["Events"]["Daily"]


def _set(mutate_template):
    return lambda spec, template: mutate_template(template)


def _globals(spec, template):
    template["Globals"] = {"Function": {"Timeout": 3}}


def _raw_function(spec, template):
    template["Resources"]["Raw"] = {"Type": "AWS::Lambda::Function", "Properties": {}}


def _standalone_role(spec, template):
    template["Resources"]["Role"] = {"Type": "AWS::IAM::Role", "Properties": {}}


def _two_functions(spec, template):
    template["Resources"]["Function2"] = copy.deepcopy(template["Resources"]["Function"])


def _no_function(spec, template):
    del template["Resources"]["Function"]


def _no_resources(spec, template):
    del template["Resources"]


def _name_literal(spec, template):
    _props(template)["FunctionName"] = "my-function"


def _name_wrong_suffix(spec, template):
    _props(template)["FunctionName"] = {"Fn::Sub": "lfg-${Stage}-other"}


def _name_missing(spec, template):
    del _props(template)["FunctionName"]


def _runtime_mismatch(spec, template):
    _props(template)["Runtime"] = "python3.14"


def _runtime_not_allowed(spec, template):
    _props(template)["Runtime"] = "python3.9"


def _arch_mismatch(spec, template):
    _props(template)["Architectures"] = ["x86_64"]


def _timeout_mismatch(spec, template):
    _props(template)["Timeout"] = 31


def _memory_mismatch(spec, template):
    _props(template)["MemorySize"] = 512


def _event_type_mismatch(spec, template):
    _event(template)["Type"] = "EventBridgeRule"


def _no_events(spec, template):
    del _props(template)["Events"]


def _two_events(spec, template):
    _props(template)["Events"]["Hourly"] = copy.deepcopy(_event(template))


def _schedule_mismatch(spec, template):
    _event(template)["Properties"]["ScheduleExpression"] = "rate(1 hour)"


def _timezone_mismatch(spec, template):
    _event(template)["Properties"]["ScheduleExpressionTimezone"] = "Europe/Dublin"


def _trigger_not_enabled(spec, template):
    spec["trigger"] = {"type": "http", "method": "GET", "path": "/x", "auth": "iam"}
    _event(template)["Type"] = "HttpApi"


def _eventbridge_pattern_mismatch(spec, template):
    spec["trigger"] = {"type": "eventbridge", "pattern": {"source": ["aws.iam"]}}
    _props(template)["Events"]["Daily"] = {
        "Type": "EventBridgeRule",
        "Properties": {"Pattern": {"source": ["aws.s3"]}},
    }


def _eventbridge_matches(spec, template):
    pattern = {"source": ["aws.iam"]}
    spec["trigger"] = {"type": "eventbridge", "pattern": pattern}
    _props(template)["Events"]["Daily"] = {
        "Type": "EventBridgeRule",
        "Properties": {"Pattern": copy.deepcopy(pattern)},
    }


MUTATIONS = [
    ("globals_present", _globals, {"LFG-TPL-002"}),
    ("raw_lambda_function", _raw_function, {"LFG-TPL-001"}),
    ("standalone_iam_role", _standalone_role, {"LFG-TPL-001"}),
    ("two_functions", _two_functions, {"LFG-TPL-001"}),
    ("no_function", _no_function, {"LFG-TPL-001"}),
    ("no_resources_key", _no_resources, {"LFG-TPL-001"}),
    ("name_literal", _name_literal, {"LFG-NAME-001"}),
    ("name_wrong_suffix", _name_wrong_suffix, {"LFG-NAME-001"}),
    ("name_missing", _name_missing, {"LFG-NAME-001"}),
    ("runtime_mismatch", _runtime_mismatch, {"LFG-SPEC-002"}),
    ("runtime_not_allowed", _runtime_not_allowed, {"LFG-RUN-001", "LFG-SPEC-002"}),
    ("arch_mismatch", _arch_mismatch, {"LFG-SPEC-002"}),
    ("timeout_mismatch", _timeout_mismatch, {"LFG-SPEC-002"}),
    ("memory_mismatch", _memory_mismatch, {"LFG-SPEC-002"}),
    ("event_type_mismatch", _event_type_mismatch, {"LFG-SPEC-002"}),
    ("no_events", _no_events, {"LFG-SPEC-002"}),
    ("two_events", _two_events, {"LFG-SPEC-002"}),
    ("schedule_expression_mismatch", _schedule_mismatch, {"LFG-SPEC-002"}),
    ("schedule_timezone_mismatch", _timezone_mismatch, {"LFG-SPEC-002"}),
    ("trigger_not_enabled", _trigger_not_enabled, {"LFG-TRG-001"}),
    ("eventbridge_pattern_mismatch", _eventbridge_pattern_mismatch, {"LFG-SPEC-002"}),
    ("eventbridge_pattern_matches", _eventbridge_matches, set()),
]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [pytest.param(m, e, id=i) for i, m, e in MUTATIONS],
)
def test_template_rule(good_dir, good_spec, good_template, mutate, expected):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    mutate(spec, template)
    result = check(spec, template, good_dir / "src", date(2026, 11, 16))
    assert rule_ids(result) == expected
