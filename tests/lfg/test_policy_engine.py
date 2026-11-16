from datetime import date

import pytest
from conftest import rule_ids
from lfg.policy import Violation, blocking, check

TODAY = date(2026, 11, 16)


def _long_timeout(spec, template):
    spec["timeout"] = 120
    template["Resources"]["Function"]["Properties"]["Timeout"] = 120


def _accept(spec, rule_id, expires):
    spec["risk_acceptances"] = [{
        "rule_id": rule_id,
        "justification": "Needed for the nightly export of a large file.",
        "accepted_by": "platform-team",
        "expires": expires,
    }]


def _run(good_dir, spec, template):
    return check(spec, template, good_dir / "src", TODAY)


def test_good_fixtures_are_clean(good_dir, good_spec, good_template):
    assert _run(good_dir, good_spec, good_template) == []


def test_long_timeout_blocks_without_acceptance(good_dir, good_spec, good_template):
    _long_timeout(good_spec, good_template)
    assert rule_ids(_run(good_dir, good_spec, good_template)) == {"LFG-RUN-002"}


def test_acceptance_marks_violation_accepted(good_dir, good_spec, good_template):
    _long_timeout(good_spec, good_template)
    _accept(good_spec, "LFG-RUN-002", "2026-12-31")
    result = _run(good_dir, good_spec, good_template)
    assert rule_ids(result) == set()
    assert [(v.rule_id, v.accepted, v.accepted_until) for v in result] == [
        ("LFG-RUN-002", True, "2026-12-31")
    ]
    assert blocking(result) == []


def test_acceptance_valid_on_expiry_day(good_dir, good_spec, good_template):
    _long_timeout(good_spec, good_template)
    _accept(good_spec, "LFG-RUN-002", "2026-11-16")
    assert rule_ids(_run(good_dir, good_spec, good_template)) == set()


def test_expired_acceptance_is_reported(good_dir, good_spec, good_template):
    _long_timeout(good_spec, good_template)
    _accept(good_spec, "LFG-RUN-002", "2026-11-15")
    result = _run(good_dir, good_spec, good_template)
    assert rule_ids(result) == {"LFG-RUN-002", "LFG-RA-001"}
    ra = [v for v in result if v.rule_id == "LFG-RA-001"]
    assert [v.location for v in ra] == ["function.spec.yaml:risk_acceptances[0]"]


@pytest.mark.parametrize("rule_id", ["LFG-IAM-001", "LFG-XYZ-999"])
def test_unacceptable_rule_is_reported(good_dir, good_spec, good_template, rule_id):
    _accept(good_spec, rule_id, "2026-12-31")
    assert rule_ids(_run(good_dir, good_spec, good_template)) == {"LFG-RA-001"}


def test_impossible_date_is_reported(good_dir, good_spec, good_template):
    _long_timeout(good_spec, good_template)
    _accept(good_spec, "LFG-RUN-002", "2027-99-99")
    assert rule_ids(_run(good_dir, good_spec, good_template)) == {"LFG-RUN-002", "LFG-RA-001"}


def test_each_bad_acceptance_reported_once(good_dir, good_spec, good_template):
    _accept(good_spec, "LFG-XYZ-999", "2026-12-31")
    good_spec["risk_acceptances"].append(dict(good_spec["risk_acceptances"][0], rule_id="LFG-IAM-001"))
    result = _run(good_dir, good_spec, good_template)
    assert [v.location for v in result] == [
        "function.spec.yaml:risk_acceptances[0]",
        "function.spec.yaml:risk_acceptances[1]",
    ]


def test_unused_acceptance_is_harmless(good_dir, good_spec, good_template):
    _accept(good_spec, "LFG-RUN-002", "2026-12-31")
    assert _run(good_dir, good_spec, good_template) == []


def test_ra_violation_cannot_be_accepted():
    from lfg.policy import acceptance
    from lfg.rules import load_catalogue

    spec = {"risk_acceptances": []}
    raw = [Violation("LFG-RA-001", "x", "somewhere")]
    assert acceptance.apply(raw, spec, load_catalogue(), TODAY) == raw


def test_results_are_sorted(good_dir, good_spec, good_template):
    _long_timeout(good_spec, good_template)
    good_template["Globals"] = {}
    good_template["Resources"]["Function"]["Properties"]["Runtime"] = "python3.9"
    result = _run(good_dir, good_spec, good_template)
    assert len(result) > 2
    assert result == sorted(result, key=lambda v: (v.rule_id, v.location))


@pytest.mark.parametrize("value", [5, "LFG-RUN-002", {"rule_id": "LFG-RUN-002"}])
def test_risk_acceptances_not_a_list(good_dir, good_spec, good_template, value):
    _long_timeout(good_spec, good_template)
    good_spec["risk_acceptances"] = value
    result = _run(good_dir, good_spec, good_template)
    assert rule_ids(result) == {"LFG-RUN-002", "LFG-RA-001"}
    assert [v.location for v in result if v.rule_id == "LFG-RA-001"] == [
        "function.spec.yaml:risk_acceptances"
    ]


def test_risk_acceptance_entry_not_a_mapping(good_dir, good_spec, good_template):
    good_spec["risk_acceptances"] = ["oops"]
    result = _run(good_dir, good_spec, good_template)
    assert [(v.rule_id, v.location) for v in result] == [
        ("LFG-RA-001", "function.spec.yaml:risk_acceptances[0]")
    ]


def test_risk_acceptance_unhashable_rule_id(good_dir, good_spec, good_template):
    _accept(good_spec, ["LFG-RUN-002"], "2026-12-31")
    assert rule_ids(_run(good_dir, good_spec, good_template)) == {"LFG-RA-001"}
