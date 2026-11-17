import copy
from datetime import date

import pytest
from conftest import rule_ids
from lfg.policy import check

SEC, LOG, REL, NET, DEP = (f"LFG-{a}-001" for a in ("SEC", "LOG", "REL", "NET", "DEP"))
HASH = "ab12" * 16


def _props(template):
    return template["Resources"]["Function"]["Properties"]


def _variables(**changes):
    def mutate(spec, template):
        _props(template)["Environment"]["Variables"].update(changes)

    return mutate


def _spec_env(**changes):
    def mutate(spec, template):
        spec["environment"].update(changes)

    return mutate


def _property(name, value):
    def mutate(spec, template):
        _props(template)[name] = value

    return mutate


def _del_property(name):
    def mutate(spec, template):
        del _props(template)[name]

    return mutate


def _logging(**changes):
    def mutate(spec, template):
        _props(template)["LoggingConfig"].update(changes)

    return mutate


def _log_group(**changes):
    def mutate(spec, template):
        template["Resources"]["LogGroup"]["Properties"].update(changes)

    return mutate


def _del_log_group_property(name):
    def mutate(spec, template):
        del template["Resources"]["LogGroup"]["Properties"][name]

    return mutate


def _del_resource(name):
    def mutate(spec, template):
        del template["Resources"][name]

    return mutate


def _set_resource(name, value):
    def mutate(spec, template):
        template["Resources"][name] = value

    return mutate


def _spec(key, value):
    def mutate(spec, template):
        spec[key] = value

    return mutate


def _dlq(**changes):
    def mutate(spec, template):
        _props(template)["DeadLetterQueue"].update(changes)

    return mutate


def _on_failure_only(on_failure):
    def mutate(spec, template):
        del _props(template)["DeadLetterQueue"]
        _props(template)["EventInvokeConfig"] = {"DestinationConfig": {"OnFailure": on_failure}}

    return mutate


def _destination_config(value, keep_dlq=True):
    def mutate(spec, template):
        if not keep_dlq:
            del _props(template)["DeadLetterQueue"]
        _props(template)["EventInvokeConfig"] = {"DestinationConfig": value}

    return mutate


def _sns_dlq(spec, template):
    spec["failure_destination"] = "sns"
    _props(template)["DeadLetterQueue"] = {"Type": "SNS", "TargetArn": {"Ref": "AlertTopic"}}


def _sns_dlq_with(**changes):
    def mutate(spec, template):
        _sns_dlq(spec, template)
        _props(template)["DeadLetterQueue"].update(changes)

    return mutate


def _eic_beside_dlq(**keys):
    def mutate(spec, template):
        _props(template)["EventInvokeConfig"] = {
            "DestinationConfig": {"OnFailure": ON_FAILURE}, **keys,
        }

    return mutate


QUEUE_ARN = {"Fn::GetAtt": ["FailureQueue", "Arn"]}
ON_FAILURE = {"Type": "SQS", "Destination": QUEUE_ARN}

MUTATIONS = [
    ("env_secret_name", _variables(DB_PASSWORD="hunter2"), {SEC}),
    ("env_secret_name_ref", _variables(API_TOKEN={"Ref": "AlertTopic"}), {SEC}),
    ("env_safe_suffix", _variables(DB_PASSWORD_PARAM="/lfg/db"), set()),
    ("env_secret_arn", _variables(SLACK_TOKEN_ARN={"Ref": "AlertTopic"}), set()),
    ("env_secret_lower_case", _variables(db_secret="x"), {SEC}),
    ("env_secret_trailing_newline", _variables(**{"DB_PASSWORD_ARN\n": "x"}), {SEC}),
    ("env_extra_key", lambda s, t: _props(t)["Environment"].update({"Extra": 1}), {SEC}),
    ("env_variables_ref", _property("Environment", {"Variables": {"Ref": "Stage"}}), {SEC}),
    ("env_variables_import", _property("Environment", {"Variables": {"Fn::ImportValue": "x"}}), {SEC}),
    ("env_empty_mapping", _property("Environment", {}), set()),
    ("spec_env_secret_name", _spec_env(API_KEY="abc"), {SEC}),
    ("spec_env_safe_suffix", _spec_env(API_KEY_NAME="abc"), set()),
    ("env_not_a_mapping", _property("Environment", "A=B"), {SEC}),
    ("env_null", _property("Environment", None), {SEC}),
    ("env_variables_a_list", _property("Environment", {"Variables": ["A"]}), {SEC}),
    ("env_variables_null", _property("Environment", {"Variables": None}), {SEC}),
    ("env_variable_name_int", lambda s, t: _props(t)["Environment"]["Variables"].update({5: "x"}), {SEC}),
    ("env_variable_name_tuple_key", lambda s, t: _props(t)["Environment"]["Variables"].update({(1, 2): "x"}), {SEC}),
    ("spec_env_not_a_mapping", _spec("environment", ["A"]), {SEC}),
    ("spec_env_name_int", lambda s, t: s["environment"].update({7: "x"}), {SEC}),
    ("no_logging_config", _del_property("LoggingConfig"), {LOG}),
    ("log_group_literal", _logging(LogGroup="/aws/lambda/x"), {LOG}),
    ("log_group_missing_resource", _del_resource("LogGroup"), {LOG}),
    ("log_group_ref_unknown", _logging(LogGroup={"Ref": "Nope"}), {LOG}),
    ("log_group_ref_wrong_type", _logging(LogGroup={"Ref": "FailureQueue"}), {LOG}),
    ("log_group_missing_key", lambda s, t: _props(t)["LoggingConfig"].pop("LogGroup"), {LOG}),
    ("log_group_ref_a_list", _logging(LogGroup={"Ref": ["LogGroup"]}), {LOG}),
    ("log_group_extra_key", _logging(LogGroup={"Ref": "LogGroup", "X": 1}), {LOG}),
    ("logging_config_string", _property("LoggingConfig", "JSON"), {LOG}),
    ("logging_config_list", _property("LoggingConfig", []), {LOG}),
    ("retention_missing", _del_log_group_property("RetentionInDays"), {LOG}),
    ("retention_mismatch", _log_group(RetentionInDays=7), {LOG}),
    ("retention_string", _log_group(RetentionInDays="30"), {LOG}),
    ("retention_bool", _log_group(RetentionInDays=True), {LOG}),
    ("retention_ref", _log_group(RetentionInDays={"Ref": "Stage"}), {LOG}),
    ("log_group_resource_not_a_mapping", _set_resource("LogGroup", "x"), {LOG, "LFG-TPL-001"}),
    ("log_group_no_properties", _set_resource("LogGroup", {"Type": "AWS::Logs::LogGroup"}), {LOG}),
    ("spec_retention_other", _spec("log_retention_days", 14), {LOG}),
    ("no_failure_destination", _del_property("DeadLetterQueue"), {REL}),
    ("on_failure_destination", _on_failure_only(ON_FAILURE), set()),
    
    ("dlq_getatt_string_form", _dlq(TargetArn={"Fn::GetAtt": "FailureQueue.Arn"}), set()),
    ("dlq_sns", _sns_dlq, set()),
    ("dlq_sns_spec_says_sqs", _dlq(Type="SNS", TargetArn={"Ref": "AlertTopic"}), {REL}),
    ("dlq_target_log_group", _dlq(TargetArn={"Fn::GetAtt": ["LogGroup", "Arn"]}), {REL}),
    ("dlq_target_function", _dlq(TargetArn={"Fn::GetAtt": ["Function", "Arn"]}), {REL}),
    ("dlq_sqs_ref_is_a_url", _dlq(TargetArn={"Ref": "FailureQueue"}), {REL}),
    ("dlq_sns_getatt", _sns_dlq_with(TargetArn={"Fn::GetAtt": ["AlertTopic", "Arn"]}), {REL}),
    ("dlq_sns_ref_to_queue", _sns_dlq_with(TargetArn={"Ref": "FailureQueue"}), {REL}),
    ("dlq_type_lower_case", _dlq(Type="sqs"), {REL}),
    ("spec_sns_with_sqs_dlq", _spec("failure_destination", "sns"), {REL}),
    ("dlq_extra_key", _dlq(Foo=1), {REL}),
    ("on_failure_extra_key", _on_failure_only({**ON_FAILURE, "Foo": 1}), {REL}),
    ("event_invoke_config_extra_key", _eic_beside_dlq(Qualifier="x"), {REL}),
    ("event_invoke_config_retries", _eic_beside_dlq(MaximumRetryAttempts=1), set()),
    ("event_invoke_config_age", _eic_beside_dlq(MaximumEventAgeInSeconds=60), set()),
    ("spec_says_none", _spec("failure_destination", "none"), {REL}),
    ("spec_failure_destination_unknown", _spec("failure_destination", "email"), {REL}),
    ("spec_failure_destination_a_list", _spec("failure_destination", ["sqs"]), {REL}),
    ("dlq_arn_string", _dlq(TargetArn="arn:aws:sqs:eu-west-1:x:q"), {REL}),
    ("dlq_ref_missing_resource", _dlq(TargetArn={"Ref": "NoSuchResource"}), {REL}),
    ("dlq_getatt_missing_resource", _dlq(TargetArn={"Fn::GetAtt": ["Nope", "Arn"]}), {REL}),
    ("dlq_getatt_other_attribute", _dlq(TargetArn={"Fn::GetAtt": ["FailureQueue", "QueueName"]}), {REL}),
    ("dlq_type_lambda", _dlq(Type="Lambda"), {REL}),
    ("dlq_type_list", _dlq(Type=["SQS"]), {REL}),
    ("dlq_missing_target", lambda s, t: _props(t)["DeadLetterQueue"].pop("TargetArn"), {REL}),
    ("dlq_string", _property("DeadLetterQueue", "arn:aws:sqs:eu-west-1:x:q"), {REL}),
    ("dlq_null", _property("DeadLetterQueue", None), {REL}),
    ("on_failure_type_lambda", _on_failure_only({"Type": "Lambda", "Destination": QUEUE_ARN}), {REL}),
    ("on_failure_arn_string", _on_failure_only({"Type": "SQS", "Destination": "arn:aws:sqs:eu-west-1:x:q"}), {REL}),
    ("on_failure_missing_resource", _on_failure_only({"Type": "SQS", "Destination": {"Ref": "Nope"}}), {REL}),
    ("on_failure_a_string", _on_failure_only("FailureQueue"), {REL}),
    (
        "on_success_present",
        _destination_config({"OnSuccess": ON_FAILURE}),
        {REL},
    ),
    (
        "on_success_beside_dlq",
        _destination_config({"OnFailure": ON_FAILURE, "OnSuccess": ON_FAILURE}),
        {REL},
    ),
    ("destination_config_other_key", _destination_config({"OnFailure": ON_FAILURE, "Other": 1}), {REL}),
    ("destination_config_a_list", _destination_config([ON_FAILURE], keep_dlq=False), {REL}),
    ("event_invoke_config_a_string", _property("EventInvokeConfig", "x"), {REL}),
    ("event_invoke_config_no_destination", _property("EventInvokeConfig", {"MaximumRetryAttempts": 1}), set()),
    ("event_invoke_config_is_not_a_destination", _destination_config({}, keep_dlq=False), {REL}),
    ("function_url_none", _property("FunctionUrlConfig", {"AuthType": "NONE"}), {NET}),
    ("function_url_iam", _property("FunctionUrlConfig", {"AuthType": "AWS_IAM"}), set()),
    ("function_url_missing_auth", _property("FunctionUrlConfig", {}), {NET}),
    ("function_url_auth_a_list", _property("FunctionUrlConfig", {"AuthType": ["AWS_IAM"]}), {NET}),
    ("function_url_a_list", _property("FunctionUrlConfig", [{"AuthType": "AWS_IAM"}]), {NET}),
    ("function_url_a_string", _property("FunctionUrlConfig", "AWS_IAM"), {NET}),
    ("function_url_null", _property("FunctionUrlConfig", None), {NET}),
]


def _run(good_dir, spec, template):
    return check(spec, template, good_dir / "src", date(2026, 11, 16))


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [pytest.param(m, e, id=i) for i, m, e in MUTATIONS],
)
def test_config_rule(good_dir, good_spec, good_template, mutate, expected):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    mutate(spec, template)
    assert rule_ids(_run(good_dir, spec, template)) == expected


def _write(content):
    def prepare(src):
        path = src / "requirements.txt"
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    return prepare


def _delete(src):
    (src / "requirements.txt").unlink()


def _dangling_symlink(src):
    (src / "requirements.txt").unlink()
    (src / "requirements.txt").symlink_to(src / "nowhere.txt")


def _directory(src):
    (src / "requirements.txt").unlink()
    (src / "requirements.txt").mkdir()


DEPENDENCIES = [
    ("deps_empty", _write(""), set()),
    ("deps_missing_file", _delete, set()),
    ("deps_comments_only", _write("# nothing\n\n"), set()),
    ("deps_pinned_hashed", _write(f"aws-lambda-powertools==3.2.0 \\\n    --hash=sha256:{HASH}\n"), set()),
    ("deps_pinned_hashed_crlf", _write(f"x==1.0 \\\r\n    --hash=sha256:{HASH}\r\n"), set()),
    ("deps_two_hashes", _write(f"x==1.0 \\\n --hash=sha256:{HASH} \\\n --hash=sha256:{HASH[::-1]}\n"), set()),
    ("deps_pinned_with_comment_line", _write(f"# note\nx==1.0 --hash=sha256:{HASH}\n"), set()),
    ("deps_two_hash_options", _write(f"x==1.0 --hash=sha256:{HASH} --hash=sha256:{HASH.upper()}"), set()),
    ("deps_marker", _write(f'x==1.0 ; python_version < "3.14" --hash=sha256:{HASH}'), set()),
    ("deps_no_binary", _write(f"x==1.0 --hash=sha256:{HASH} --no-binary :all:"), {DEP}),
    ("deps_global_option", _write(f"x==1.0 --hash=sha256:{HASH} --global-option=x"), {DEP}),
    ("deps_at_file", _write("x @ file:/tmp/x"), {DEP}),
    ("deps_at_marker_free", _write(f"x@1.0==1.0 --hash=sha256:{HASH}"), {DEP}),
    ("deps_star_version", _write(f"x==1.* --hash=sha256:{HASH}"), {DEP}),
    ("deps_triple_equals", _write(f"x===1.0 --hash=sha256:{HASH}"), {DEP}),
    ("deps_hash_65", _write(f"x==1.0 --hash=sha256:{HASH}a"), {DEP}),
    ("deps_hash_63", _write(f"x==1.0 --hash=sha256:{HASH[:-1]}"), {DEP}),
    ("deps_hash_not_hex", _write(f"x==1.0 --hash=sha256:{'g' * 64}"), {DEP}),
    ("deps_two_pins", _write(f"x==1.0==2.0 --hash=sha256:{HASH}"), {DEP}),
    ("deps_junk_after_version", _write(f"x==1.0 junk --hash=sha256:{HASH}"), {DEP}),
    ("deps_bom_then_include", _write(b"\xef\xbb\xbf-r other.txt\n"), {DEP}),
    ("deps_bom_then_pinned", _write(b"\xef\xbb\xbfx==1.0 --hash=sha256:" + HASH.encode()), set()),
    ("deps_dangling_symlink", _dangling_symlink, {DEP}),
    ("deps_unpinned", _write("requests"), {DEP}),
    ("deps_range", _write("requests>=2.0"), {DEP}),
    ("deps_pinned_no_hash", _write("requests==2.32.3"), {DEP}),
    ("deps_short_hash", _write("requests==2.32.3 --hash=sha256:abcd"), {DEP}),
    ("deps_hash_in_comment", _write(f"requests==2.32.3 # --hash=sha256:{HASH}"), {DEP}),
    ("deps_hash_only", _write(f"--hash=sha256:{HASH}"), {DEP}),
    ("deps_include", _write("-r other.txt"), {DEP}),
    ("deps_index_option", _write(f"--index-url https://x.example/simple==1 --hash=sha256:{HASH}"), {DEP}),
    ("deps_url", _write("git+https://github.com/x/y.git"), {DEP}),
    ("deps_url_pinned", _write(f"x==1 @ https://x.example/x.whl --hash=sha256:{HASH}"), {DEP}),
    ("deps_one_bad_of_two", _write(f"x==1 --hash=sha256:{HASH}\ny\n"), {DEP}),
    ("deps_not_utf8", _write(b"\xff\xfe\x00x"), {DEP}),
    ("deps_is_a_directory", _directory, {DEP}),
]


@pytest.mark.parametrize(
    ("prepare", "expected"),
    [pytest.param(p, e, id=i) for i, p, e in DEPENDENCIES],
)
def test_dependency_rule(good_dir, good_spec, good_template, prepare, expected):
    prepare(good_dir / "src")
    assert rule_ids(_run(good_dir, good_spec, good_template)) == expected


def test_source_dir_missing_is_not_a_dependency_violation(good_dir, good_spec, good_template):
    result = check(good_spec, good_template, good_dir / "nowhere", date(2026, 11, 16))
    assert rule_ids(result) == set()


def test_locations(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _variables(DB_PASSWORD="x")(spec, template)
    _log_group(RetentionInDays=7)(spec, template)
    _dlq(TargetArn="arn:x")(spec, template)
    _property("FunctionUrlConfig", {"AuthType": "NONE"})(spec, template)
    base = "template.yaml:Resources.Function.Properties"
    locations = {v.rule_id: v.location for v in _run(good_dir, spec, template)}
    assert locations == {
        SEC: f"{base}.Environment.Variables.DB_PASSWORD",
        LOG: "template.yaml:Resources.LogGroup.Properties.RetentionInDays",
        REL: f"{base}.DeadLetterQueue.TargetArn",
        NET: f"{base}.FunctionUrlConfig.AuthType",
    }


def test_acceptance_of_function_url(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _property("FunctionUrlConfig", {"AuthType": "NONE"})(spec, template)
    spec["risk_acceptances"] = [{
        "rule_id": NET, "justification": "Public by design, fronted by a gateway.",
        "accepted_by": "someone", "expires": "2026-12-01",
    }]
    result = _run(good_dir, spec, template)
    assert rule_ids(result) == set()
    assert [v.rule_id for v in result if v.accepted] == [NET]


def test_no_secret_value_in_message(good_dir, good_spec, good_template):
    spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
    _variables(DB_PASSWORD="hunter2")(spec, template)
    assert all("hunter2" not in v.message for v in _run(good_dir, spec, template))


def test_on_failure_locations(good_dir, good_spec, good_template):
    base = "template.yaml:Resources.Function.Properties.EventInvokeConfig.DestinationConfig.OnFailure"
    for on_failure, suffix in (
        ({"Type": "SQS", "Destination": "arn:x"}, ".Destination"),
        ({"Type": "Lambda", "Destination": QUEUE_ARN}, ""),
        ("x", ""),
    ):
        spec, template = copy.deepcopy(good_spec), copy.deepcopy(good_template)
        _on_failure_only(on_failure)(spec, template)
        assert [v.location for v in _run(good_dir, spec, template)] == [base + suffix]
