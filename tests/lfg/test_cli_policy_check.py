import json

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


def test_schema_errors_stop_the_checks(good_dir, capsys):
    _edit(good_dir / "function.spec.yaml", "timeout: 30", "timeout: 901")
    _edit(good_dir / "template.yaml", "Timeout: 30", "Timeout: 120")
    assert main(["policy-check", str(good_dir)]) == 1
    out = capsys.readouterr().out
    assert "timeout: " in out
    assert "LFG-" not in out


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
        "function": "iam-key-age-audit", "blocking": 0, "violations": [],
    }


def test_bad_today(good_dir, capsys):
    assert main(["policy-check", str(good_dir), "--today", "not-a-date"]) == 2
    err = capsys.readouterr().err
    assert "--today" in err
    assert "Traceback" not in err


def test_bad_today_shape(good_dir):
    assert main(["policy-check", str(good_dir), "--today", "2026-1-5"]) == 2
