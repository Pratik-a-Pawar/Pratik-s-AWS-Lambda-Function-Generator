"""Lab 00 acceptance checks: workstation tools, Python version, research answers, AWS guardrails.

Run with `lfg labcheck 00`. The two AWS checks run only when a profile or access key is
configured, so export AWS_PROFILE before running them.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ANSWERS = ROOT / "labs" / "00-workstation" / "answers.md"
TOOLS = ["git", "python3", "aws", "sam", "terraform", "docker", "gh", "claude"]
QUESTIONS = [f"Q{number}" for number in range(1, 7)]
MIN_ANSWER_CHARS = 40
AWS_TIMEOUT_SECONDS = 60

QUESTION_HEADING = re.compile(r"^## (Q[1-6])(?![0-9])")
LEVEL_1_OR_2_HEADING = re.compile(r"^#{1,2}\s")
FENCE = re.compile(r"^\s*(```|~~~)")

needs_aws_credentials = pytest.mark.skipif(
    not (os.environ.get("AWS_PROFILE") or os.environ.get("AWS_ACCESS_KEY_ID")),
    reason="no AWS credentials configured: export AWS_PROFILE to run this check",
)
needs_aws_cli = pytest.mark.skipif(
    shutil.which("aws") is None,
    reason="the aws command is not on PATH (see test_tools_on_path[aws])",
)


def answer_sections(text: str) -> dict[str, str]:
    """Map each `## Qn` heading to the text under it, up to the next level 1 or 2 heading."""
    sections: dict[str, list[str]] = {}
    current = None
    in_fence = False
    for line in text.splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and LEVEL_1_OR_2_HEADING.match(line):
            match = QUESTION_HEADING.match(line)
            current = match.group(1) if match else None
            if current:
                sections.setdefault(current, [])
            continue
        if current:
            sections[current].append(line)
    return {question: "\n".join(lines) for question, lines in sections.items()}


def answer_problems(text: str) -> list[str]:
    """Return one message for each question that is missing, too short or still TODO."""
    sections = answer_sections(text)
    problems = []
    for question in QUESTIONS:
        if question not in sections:
            problems.append(f"no '## {question}' heading")
            continue
        body = " ".join(sections[question].split())
        if "TODO" in body:
            problems.append(f"the answer under '## {question}' still contains TODO")
        elif len(body) < MIN_ANSWER_CHARS:
            problems.append(
                f"the answer under '## {question}' is {len(body)} characters;"
                f" write at least {MIN_ANSWER_CHARS}"
            )
    return problems


def run_aws(*args: str) -> dict:
    """Run an aws command and return its JSON output; any failure is an assertion failure."""
    command = ["aws", *args, "--output", "json"]
    shown = " ".join(command)
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False,
            timeout=AWS_TIMEOUT_SECONDS, env={**os.environ, "AWS_PAGER": ""},
        )
    except FileNotFoundError:
        raise AssertionError("the aws command is not on PATH: install AWS CLI v2") from None
    except subprocess.TimeoutExpired:
        raise AssertionError(
            f"'{shown}' did not finish within {AWS_TIMEOUT_SECONDS} seconds;"
            " check your network connection and sign-in"
        ) from None
    error = " ".join(result.stderr.split())[-300:]
    assert result.returncode == 0, (
        f"'{shown}' failed with exit code {result.returncode}: {error}\n"
        "If your SSO session has expired, sign in again (aws sso login) and re-run."
    )
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        output = None
    assert isinstance(output, dict), (
        f"'{shown}' did not print a JSON object: {result.stdout.strip()[:200]!r}"
    )
    return output


@pytest.mark.parametrize("tool", TOOLS)
def test_tools_on_path(tool):
    assert shutil.which(tool) is not None, (
        f"'{tool}' is not on PATH inside WSL; install it (Lab 00 task list) and open a new shell"
    )


def test_python_version():
    found = ".".join(str(part) for part in sys.version_info[:3])
    assert sys.version_info >= (3, 12), (
        f"the checks ran on Python {found}; the project needs 3.12 or later."
        " Recreate .venv with a newer python3"
    )


def test_answers_filled():
    relative = ANSWERS.relative_to(ROOT)
    assert ANSWERS.is_file(), f"create {relative} with the headings '## Q1' to '## Q6'"
    try:
        text = ANSWERS.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AssertionError(f"cannot read {relative} as UTF-8 text: {exc}") from None
    problems = answer_problems(text)
    assert not problems, f"{relative}:\n- " + "\n- ".join(problems)


@pytest.mark.aws
@needs_aws_credentials
@needs_aws_cli
def test_not_root():
    arn = run_aws("sts", "get-caller-identity").get("Arn")
    assert isinstance(arn, str), "aws sts get-caller-identity returned no Arn"
    assert not arn.endswith(":root"), (
        "these credentials are the account's root user. Sign in with your non-root profile"
        " (export AWS_PROFILE=<profile>) and keep root for the tasks only root can do"
    )


@pytest.mark.aws
@needs_aws_credentials
@needs_aws_cli
def test_budget_exists():
    account = run_aws("sts", "get-caller-identity").get("Account")
    assert isinstance(account, str), "aws sts get-caller-identity returned no Account"
    budgets = run_aws("budgets", "describe-budgets", "--account-id", account).get("Budgets")
    assert budgets, (
        "the account has no AWS Budgets budget. Create a monthly cost budget with an alert"
        " (Lab 00 task list), then re-run"
    )
