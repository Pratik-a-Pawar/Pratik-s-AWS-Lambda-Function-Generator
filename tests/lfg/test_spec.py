import copy

import pytest
from lfg.spec import SpecLoadError, load_spec, validate_spec

VALID_ACCEPTANCE = {
    "rule_id": "LFG-RUN-002",
    "justification": "Twenty characters ok",
    "accepted_by": "pratik-a-pawar",
    "expires": "2027-01-31",
}


def _set(spec, key, value):
    spec[key] = value


def _set_trigger_type(spec, value):
    spec["trigger"]["type"] = value


def _del_expression(spec):
    del spec["trigger"]["expression"]


def _set_action(spec):
    spec["permissions"][0]["actions"] = ["ListUsers"]


def _set_reason(spec):
    spec["permissions"][0]["reason"] = "need it"


def _acceptance(**changes):
    def mutate(spec):
        spec["risk_acceptances"] = [{**VALID_ACCEPTANCE, **changes}]

    return mutate


def _delete(key):
    def mutate(spec):
        del spec[key]

    return mutate


CASES = {
    "name_uppercase": (lambda s: _set(s, "name", "Bad_Name"), "name"),
    "name_too_short": (lambda s: _set(s, "name", "ab"), "name"),
    "purpose_too_short": (lambda s: _set(s, "purpose", "short"), "purpose"),
    "runtime_unknown": (lambda s: _set(s, "runtime", "python3.9"), "runtime"),
    "arch_unknown": (lambda s: _set(s, "architecture", "arm"), "architecture"),
    "trigger_type_unknown": (lambda s: _set_trigger_type(s, "kinesis"), "trigger"),
    "schedule_missing_expression": (_del_expression, "trigger"),
    "eventbridge_empty_pattern": (
        lambda s: _set(s, "trigger", {"type": "eventbridge", "pattern": {}}),
        "trigger",
    ),
    "action_bad_format": (_set_action, "permissions[0].actions[0]"),
    "reason_too_short": (_set_reason, "permissions[0].reason"),
    "timeout_too_high": (lambda s: _set(s, "timeout", 901), "timeout"),
    "memory_too_low": (lambda s: _set(s, "memory", 64), "memory"),
    "retention_not_allowed": (lambda s: _set(s, "log_retention_days", 45), "log_retention_days"),
    "classification_unknown": (
        lambda s: _set(s, "data_classification", "secret"),
        "data_classification",
    ),
    "failure_destination_unknown": (
        lambda s: _set(s, "failure_destination", "email"),
        "failure_destination",
    ),
    "acceptance_bad_rule_id": (_acceptance(rule_id="IAM-5"), "risk_acceptances[0].rule_id"),
    "acceptance_short_justification": (
        _acceptance(justification="12345"),
        "risk_acceptances[0].justification",
    ),
    "unknown_top_level_key": (lambda s: _set(s, "backdoor", True), "(root)"),
    "missing_required": (_delete("owner"), "(root)"),
    "secret_bad_source": (
        lambda s: _set(
            s, "secrets", [{"name": "DB_PASSWORD_PARAM", "source": "env", "reference": "/x"}]
        ),
        "secrets[0].source",
    ),
}


def test_good_spec_has_no_errors(good_spec):
    assert validate_spec(good_spec) == []


@pytest.mark.parametrize("mutate,expected", CASES.values(), ids=CASES.keys())
def test_invalid_spec_reports_path(good_spec, mutate, expected):
    spec = copy.deepcopy(good_spec)
    mutate(spec)
    errors = validate_spec(spec)
    assert expected in [e.path for e in errors], errors


def test_errors_sorted_by_path(good_spec):
    good_spec["timeout"] = 901
    good_spec["name"] = "Bad"
    paths = [e.path for e in validate_spec(good_spec)]
    assert paths == sorted(paths)


def test_valid_eventbridge_trigger(good_spec):
    good_spec["trigger"] = {"type": "eventbridge", "pattern": {"source": ["aws.ec2"]}}
    assert validate_spec(good_spec) == []


def test_valid_http_trigger(good_spec):
    good_spec["trigger"] = {"type": "http", "method": "GET", "path": "/health", "auth": "iam"}
    assert validate_spec(good_spec) == []


def test_valid_risk_acceptance(good_spec):
    good_spec["risk_acceptances"] = [VALID_ACCEPTANCE]
    assert validate_spec(good_spec) == []


def test_load_missing_file(tmp_path):
    with pytest.raises(SpecLoadError):
        load_spec(tmp_path / "nope.yaml")


def test_load_invalid_yaml(tmp_path):
    path = tmp_path / "s.yaml"
    path.write_text(": :\n- [")
    with pytest.raises(SpecLoadError):
        load_spec(path)


def test_load_non_mapping(tmp_path):
    path = tmp_path / "s.yaml"
    path.write_text("- a\n- b\n")
    with pytest.raises(SpecLoadError):
        load_spec(path)


def test_load_impossible_date(tmp_path):
    path = tmp_path / "s.yaml"
    path.write_text("expires: 2027-02-30\n")
    with pytest.raises(SpecLoadError):
        load_spec(path)


def test_load_binary_file(tmp_path):
    path = tmp_path / "s.yaml"
    path.write_bytes(b"\xff\xfe\x00\x80\x81")
    with pytest.raises(SpecLoadError):
        load_spec(path)


def test_unquoted_date_is_normalised(good_dir):
    spec_file = good_dir / "function.spec.yaml"
    text = spec_file.read_text().replace(
        "risk_acceptances: []",
        "risk_acceptances:\n"
        "  - rule_id: LFG-RUN-002\n"
        "    justification: Twenty characters ok\n"
        "    accepted_by: pratik-a-pawar\n"
        "    expires: 2027-01-31\n",
    )
    spec_file.write_text(text)
    spec = load_spec(spec_file)
    assert spec["risk_acceptances"][0]["expires"] == "2027-01-31"
    assert validate_spec(spec) == []
