"""Tests for the Lab 00 acceptance check's own logic (labs/checks/test_lab00.py)."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "labs" / "00-workstation" / "answers.md"
SKELETON = ROOT / "labs" / "00-workstation" / "skeleton" / "labs" / "00-workstation" / "answers.md"
ANSWER = "An answer that is comfortably longer than forty characters."


def answers(**overrides: str) -> str:
    bodies = {f"Q{n}": ANSWER for n in range(1, 7)} | overrides
    return "# Answers\n\n" + "".join(f"## {q} Title\n\n{body}\n\n" for q, body in bodies.items())


def test_complete_answers_have_no_problems(lab00):
    assert lab00.answer_problems(answers()) == []


def test_reference_answers_have_no_problems(lab00):
    assert lab00.answer_problems(REFERENCE.read_text(encoding="utf-8")) == []


def test_skeleton_answers_are_all_todo(lab00):
    problems = lab00.answer_problems(SKELETON.read_text(encoding="utf-8"))
    assert problems == [f"the answer under '## Q{n}' still contains TODO" for n in range(1, 7)]


def test_missing_heading_is_named(lab00):
    text = answers().replace("## Q4 Title", "## Question four")
    assert lab00.answer_problems(text) == ["no '## Q4' heading"]


def test_short_answer_reports_its_length(lab00):
    assert lab00.answer_problems(answers(Q2="Too short.")) == [
        "the answer under '## Q2' is 10 characters; write at least 40"
    ]


def test_whitespace_does_not_count_towards_length(lab00):
    assert lab00.answer_problems(answers(Q3="word " + " " * 60 + "\n" * 20)) == [
        "the answer under '## Q3' is 4 characters; write at least 40"
    ]


def test_todo_anywhere_in_an_answer_fails(lab00):
    assert lab00.answer_problems(answers(Q5=ANSWER + " TODO: add the URL")) == [
        "the answer under '## Q5' still contains TODO"
    ]


def test_answer_ends_at_the_next_level_2_heading(lab00):
    text = answers(Q6="Short.") + "## Notes\n\n" + ANSWER + "\n"
    assert lab00.answer_problems(text) == [
        "the answer under '## Q6' is 6 characters; write at least 40"
    ]


def test_subheadings_stay_inside_an_answer(lab00):
    text = answers(Q1="### Part one\n\n" + ANSWER)
    assert "Part one" in lab00.answer_sections(text)["Q1"]


def test_q10_is_not_q1(lab00):
    text = answers().replace("## Q1 Title", "## Q10 Title")
    assert lab00.answer_problems(text) == ["no '## Q1' heading"]


def test_headings_inside_fences_are_ignored(lab00):
    text = answers(Q2=ANSWER + "\n\n```\n## Q3 inside a fence\n```")
    sections = lab00.answer_sections(text)
    assert "## Q3 inside a fence" in sections["Q2"]
    assert sections["Q3"].strip() == ANSWER


def test_missing_answers_file_fails_with_a_message(lab00, monkeypatch, tmp_path):
    monkeypatch.setattr(lab00, "ROOT", tmp_path)
    monkeypatch.setattr(lab00, "ANSWERS", tmp_path / "labs" / "00-workstation" / "answers.md")
    with pytest.raises(AssertionError, match="create labs/00-workstation/answers.md"):
        lab00.test_answers_filled()


def test_problems_are_listed_in_the_failure(lab00, monkeypatch, tmp_path):
    path = tmp_path / "answers.md"
    path.write_text(answers(Q1="TODO", Q2="short"), encoding="utf-8")
    monkeypatch.setattr(lab00, "ROOT", tmp_path)
    monkeypatch.setattr(lab00, "ANSWERS", path)
    with pytest.raises(AssertionError) as failure:
        lab00.test_answers_filled()
    assert "'## Q1' still contains TODO" in str(failure.value)
    assert "'## Q2' is 5 characters" in str(failure.value)


@pytest.fixture
def fake_aws(tmp_path, monkeypatch):
    """Put a fake `aws` on PATH that answers each service with (exit code, stdout, stderr)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir))

    def install(responses: dict[str, tuple[int, str, str]]) -> None:
        script = bin_dir / "aws"
        script.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"responses = json.loads({json.dumps(json.dumps(responses))})\n"
            "code, out, err = responses[sys.argv[1]]\n"
            "sys.stdout.write(out)\n"
            "sys.stderr.write(err)\n"
            "sys.exit(code)\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

    return install


def identity(arn: str) -> tuple[int, str, str]:
    return 0, json.dumps({"Arn": arn, "Account": "ACCOUNT", "UserId": "USER"}), ""


def test_run_aws_returns_the_json_object(lab00, fake_aws):
    fake_aws({"sts": identity("arn:aws:sts::ACCOUNT:assumed-role/admin/me")})
    assert lab00.run_aws("sts", "get-caller-identity")["Account"] == "ACCOUNT"


def test_run_aws_reports_a_failing_command(lab00, fake_aws):
    fake_aws({"sts": (255, "", "\nThe SSO session has expired\n")})
    with pytest.raises(AssertionError, match="exit code 255: The SSO session has expired"):
        lab00.run_aws("sts", "get-caller-identity")


@pytest.mark.parametrize("stdout", ["not json", "[1, 2]", ""])
def test_run_aws_reports_output_that_is_not_a_json_object(lab00, fake_aws, stdout):
    fake_aws({"sts": (0, stdout, "")})
    with pytest.raises(AssertionError, match="did not print a JSON object"):
        lab00.run_aws("sts", "get-caller-identity")


def test_run_aws_reports_a_missing_cli(lab00, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(AssertionError, match="not on PATH"):
        lab00.run_aws("sts", "get-caller-identity")


def test_root_identity_fails(lab00, fake_aws):
    fake_aws({"sts": identity("arn:aws:iam::ACCOUNT:root")})
    with pytest.raises(AssertionError, match="root user"):
        lab00.test_not_root()


def test_non_root_identity_passes(lab00, fake_aws):
    fake_aws({"sts": identity("arn:aws:sts::ACCOUNT:assumed-role/AWSReservedSSO_admin/me")})
    lab00.test_not_root()


@pytest.mark.parametrize("output", [{"Budgets": []}, {}])
def test_no_budget_fails(lab00, fake_aws, output):
    fake_aws({"sts": identity("arn:aws:iam::ACCOUNT:user/me"), "budgets": (0, json.dumps(output), "")})
    with pytest.raises(AssertionError, match="no AWS Budgets budget"):
        lab00.test_budget_exists()


def test_one_budget_passes(lab00, fake_aws):
    budgets = {"Budgets": [{"BudgetName": "monthly"}]}
    fake_aws({"sts": identity("arn:aws:iam::ACCOUNT:user/me"), "budgets": (0, json.dumps(budgets), "")})
    lab00.test_budget_exists()
