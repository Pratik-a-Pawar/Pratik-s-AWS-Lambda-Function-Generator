import json

import pytest
from lfg.cli import main


def _edit(path, old, new):
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new))


def _slow(good_dir):
    _edit(good_dir / "template.yaml", "Timeout: 30", "Timeout: 120")
    _edit(good_dir / "function.spec.yaml", "timeout: 30", "timeout: 120")


ACCEPTANCE = (
    "risk_acceptances:\n  - rule_id: LFG-RUN-002\n"
    "    justification: The export job needs two minutes to finish.\n"
    "    accepted_by: someone\n    expires: 2026-12-01\n"
)


def test_good(good_dir, capsys):
    assert main(["policy-check", str(good_dir)]) == 0
    assert capsys.readouterr().out.strip() == "OK: iam-key-age-audit (0 violations)"


def test_violation(good_dir, capsys):
    _slow(good_dir)
    assert main(["policy-check", str(good_dir), "--today", "2026-11-16"]) == 1
    out = capsys.readouterr().out
    assert "LFG-RUN-002" in out
    assert "template.yaml:Resources.Function.Properties.Timeout" in out
    assert out.strip().splitlines()[-1] == "BLOCKED: 1 violation(s)"


def test_accepted(good_dir, capsys):
    _slow(good_dir)
    _edit(good_dir / "function.spec.yaml", "risk_acceptances: []\n", ACCEPTANCE)
    assert main(["policy-check", str(good_dir), "--today", "2026-11-16"]) == 0
    out = capsys.readouterr().out
    assert "ACCEPTED until 2026-12-01" in out
    assert "OK: iam-key-age-audit (0 violations)" in out


def test_acceptance_expired(good_dir, capsys):
    _slow(good_dir)
    _edit(good_dir / "function.spec.yaml", "risk_acceptances: []\n", ACCEPTANCE)
    assert main(["policy-check", str(good_dir), "--today", "2027-01-01"]) == 1


def _bad_spec(good_dir):
    _edit(good_dir / "function.spec.yaml", "timeout: 30", "timeout: 901")
    _edit(good_dir / "template.yaml", "Timeout: 30", "Timeout: 120")


def test_schema_errors_stop_the_checks(good_dir, capsys):
    _bad_spec(good_dir)
    assert main(["policy-check", str(good_dir)]) == 1
    out = capsys.readouterr().out
    assert "timeout: " in out
    assert "LFG-" not in out


def test_schema_errors_in_json(good_dir, capsys):
    _bad_spec(good_dir)
    assert main(["policy-check", str(good_dir), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["function"] == "iam-key-age-audit"
    assert data["spec_errors"] and set(data["spec_errors"][0]) == {"path", "message"}
    assert data["blocking"] == 0
    assert data["violations"] == []


def test_schema_errors_in_json_without_a_name(good_dir, capsys):
    _edit(good_dir / "function.spec.yaml", "name: iam-key-age-audit\n", "")
    assert main(["policy-check", str(good_dir), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["function"] is None


def test_unusable_template_beats_schema_errors(good_dir, capsys):
    _bad_spec(good_dir)
    (good_dir / "template.yaml").unlink()
    assert main(["policy-check", str(good_dir)]) == 2
    assert "template.yaml" in capsys.readouterr().err


def test_missing_src_directory(good_dir, capsys):
    import shutil

    shutil.rmtree(good_dir / "src")
    assert main(["policy-check", str(good_dir)]) == 2
    err = capsys.readouterr().err
    assert "src" in err and len(err.strip().splitlines()) == 1


def test_src_without_requirements(good_dir, capsys):
    (good_dir / "src" / "requirements.txt").unlink()
    assert main(["policy-check", str(good_dir)]) == 0


def test_src_is_a_file(good_dir):
    import shutil

    shutil.rmtree(good_dir / "src")
    (good_dir / "src").write_text("x")
    assert main(["policy-check", str(good_dir)]) == 2


DEEP = "[" * 100000


def _deep_metadata(good_dir):
    path = good_dir / "template.yaml"
    path.write_text(path.read_text() + "Metadata: " + "{a: " * 600 + "1" + "}" * 600 + "\n")


@pytest.mark.parametrize("command", ["policy-check", "validate-spec"])
def test_deeply_nested_spec(good_dir, capsys, command):
    (good_dir / "function.spec.yaml").write_text(DEEP)
    assert main([command, str(good_dir)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and len(err.strip().splitlines()) == 1


def test_deeply_nested_template(good_dir, capsys):
    (good_dir / "template.yaml").write_text(DEEP)
    assert main(["policy-check", str(good_dir)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and len(err.strip().splitlines()) == 1


def test_template_nested_600_deep(good_dir, capsys):
    _deep_metadata(good_dir)
    assert main(["policy-check", str(good_dir)]) == 2
    err = capsys.readouterr().err
    assert "nested too deeply" in err and "Traceback" not in err


def test_missing_template(good_dir, capsys):
    (good_dir / "template.yaml").unlink()
    assert main(["policy-check", str(good_dir)]) == 2
    err = capsys.readouterr().err
    assert "template.yaml" in err
    assert "Traceback" not in err
    assert len(err.strip().splitlines()) == 1


def test_invalid_template_yaml(good_dir, capsys):
    (good_dir / "template.yaml").write_text("a: [unclosed\nb: {\n")
    assert main(["policy-check", str(good_dir)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert len(err.strip().splitlines()) == 1


def test_missing_spec(good_dir, capsys):
    (good_dir / "function.spec.yaml").unlink()
    assert main(["policy-check", str(good_dir)]) == 2
    assert "function.spec.yaml" in capsys.readouterr().err


def test_unreadable_template(good_dir, capsys):
    (good_dir / "template.yaml").write_bytes(b"\xff\xfe\x00")
    assert main(["policy-check", str(good_dir)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_json_format(good_dir, capsys):
    _slow(good_dir)
    assert main(["policy-check", str(good_dir), "--format", "json", "--today", "2026-11-16"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["function"] == "iam-key-age-audit"
    assert data["blocking"] == 1
    assert set(data["violations"][0]) == {"rule_id", "message", "location", "accepted", "accepted_until"}


def test_json_format_good(good_dir, capsys):
    assert main(["policy-check", str(good_dir), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "function": "iam-key-age-audit", "spec_errors": [], "blocking": 0, "violations": [],
    }


def test_bad_today(good_dir, capsys):
    assert main(["policy-check", str(good_dir), "--today", "not-a-date"]) == 2
    err = capsys.readouterr().err
    assert "--today" in err
    assert "Traceback" not in err


def test_bad_today_shape(good_dir):
    assert main(["policy-check", str(good_dir), "--today", "2026-1-5"]) == 2
