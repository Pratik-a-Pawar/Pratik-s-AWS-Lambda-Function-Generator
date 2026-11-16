import re
from pathlib import Path

import pytest
import yaml
from lfg.rules import Catalogue, Rule, load_catalogue

ROOT = Path(__file__).resolve().parents[2]
STANDARD = ROOT / "standards" / "secure-lambda-standard.md"

EXPECTED_IDS = {
    "LFG-TPL-001", "LFG-TPL-002", "LFG-TPL-003", "LFG-TPL-004", "LFG-NAME-001", "LFG-SPEC-001", "LFG-SPEC-002",
    "LFG-TRG-001", "LFG-RA-001", "LFG-IAM-001", "LFG-IAM-002", "LFG-IAM-003",
    "LFG-IAM-004", "LFG-IAM-005", "LFG-IAM-006", "LFG-IAM-007", "LFG-IAM-008",
    "LFG-SEC-001", "LFG-SEC-002", "LFG-RUN-001", "LFG-RUN-002", "LFG-LOG-001",
    "LFG-REL-001", "LFG-DEP-001", "LFG-NET-001", "LFG-COD-001", "LFG-COD-002",
    "LFG-COD-003",
}


def test_catalogue_has_exactly_the_expected_rules():
    catalogue = load_catalogue()
    assert isinstance(catalogue, Catalogue)
    assert set(catalogue.rules) == EXPECTED_IDS
    assert len(catalogue.rules) == 28


def test_every_rule_is_well_formed():
    for rule_id, rule in load_catalogue().rules.items():
        assert isinstance(rule, Rule)
        assert rule.id == rule_id
        assert rule.klass in {"deny", "require", "accept"}
        assert rule.severity in {"critical", "high", "medium", "low"}
        assert rule.enforced_by in {"policy-check", "scanner", "review"}
        assert rule.title.strip()
        assert rule.summary.strip()
        assert rule.cwe is None or re.fullmatch(r"CWE-\d+", rule.cwe)


def test_rules_without_a_cwe_store_none():
    rules = load_catalogue().rules
    assert rules["LFG-NAME-001"].cwe is None
    assert rules["LFG-IAM-001"].cwe == "CWE-732"


def test_enabled_triggers_and_resource_types():
    catalogue = load_catalogue()
    assert catalogue.enabled_triggers == frozenset({"schedule", "eventbridge"})
    assert catalogue.allowed_resource_types == frozenset(
        {"AWS::Serverless::Function", "AWS::Logs::LogGroup", "AWS::SQS::Queue", "AWS::SNS::Topic"}
    )


def test_property_allow_lists_are_loaded():
    catalogue = load_catalogue()
    assert catalogue.allowed_function_attributes == frozenset(
        {"Type", "Properties", "Metadata", "DependsOn"}
    )
    assert "Policies" in catalogue.allowed_function_properties
    assert "AssumeRolePolicyDocument" not in catalogue.allowed_function_properties
    assert set(catalogue.allowed_event_properties) == {"ScheduleV2", "EventBridgeRule"}
    assert "Pattern" in catalogue.allowed_event_properties["EventBridgeRule"]
    assert isinstance(catalogue.allowed_event_properties["ScheduleV2"], frozenset)


def test_allowed_template_sections_are_loaded():
    sections = load_catalogue().allowed_template_sections
    assert isinstance(sections, frozenset)
    assert {"Transform", "Resources", "Parameters", "Globals"} <= sections
    assert "Conditions" not in sections


def test_lists_and_patterns_are_loaded():
    catalogue = load_catalogue()
    assert "ec2:Describe*" in catalogue.wildcard_only_actions
    assert "iam:PassRole" in catalogue.sensitive_actions
    assert re.search(catalogue.secret_name_pattern, "DB_PASSWORD")
    assert catalogue.secret_name_safe_suffixes == ("_ARN", "_NAME", "_PARAM", "_ID")


def test_standard_and_catalogue_do_not_drift():
    text = STANDARD.read_text(encoding="utf-8")
    headings = re.findall(r"^### (LFG-\S+)\s*$", text, flags=re.MULTILINE)
    assert len(headings) == len(set(headings))
    assert set(headings) == set(load_catalogue().rules)


def test_duplicate_rule_id_is_rejected(tmp_path):
    data = yaml.safe_load((ROOT / "standards" / "rules.yaml").read_text(encoding="utf-8"))
    data["rules"].append(dict(data["rules"][0]))
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_catalogue(path)
