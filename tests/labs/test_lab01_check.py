"""Tests for the Lab 01 acceptance check's own logic (labs/checks/test_lab01.py)."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs" / "threat-model.md"
SKELETON = ROOT / "labs" / "01-threat-model" / "skeleton" / "docs" / "threat-model.md"

HEADER = "| ID | Component | STRIDE | Threat | Mitigation | Status |\n|---|---|---|---|---|---|\n"


def checks(module):
    return [getattr(module, name) for name in dir(module) if name.startswith("test_")]


def use(lab01, monkeypatch, tmp_path: Path, text: str | None) -> None:
    """Point the check at docs/threat-model.md in a temporary repository."""
    path = tmp_path / "docs" / "threat-model.md"
    if text is not None:
        path.parent.mkdir()
        path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(lab01, "ROOT", tmp_path)
    monkeypatch.setattr(lab01, "THREAT_MODEL", path)


def test_sections_split_on_level_2_headings(lab01):
    text = "# Title\nintro\n## One\na\n### Sub\nb\n## Two\nc\n# Other\nd\n"
    assert lab01.sections(text) == {"One": "a\n### Sub\nb", "Two": "c"}


def test_sections_ignore_headings_inside_fences(lab01):
    text = "## Data flow diagram\n```\n## not a heading\n```\n## Assets\nx\n"
    found = lab01.sections(text)
    assert list(found) == ["Data flow diagram", "Assets"]
    assert "## not a heading" in found["Data flow diagram"]


def test_sections_strip_closing_hashes(lab01):
    assert lab01.sections("## Threats ##\nx\n") == {"Threats": "x"}


@pytest.mark.parametrize(("body", "expected"), [
    ("```\nA -> B\n```", True),
    ("~~~text\nA -> B\n~~~", True),
    ("```\nnever closed", False),
    ("A -> B", False),
])
def test_has_fenced_block(lab01, body, expected):
    assert lab01.has_fenced_block(body) is expected


def test_first_table_parses_header_and_rows(lab01):
    body = "Intro\n\n" + HEADER + "| T1 | c | Spoofing | t | m | Built |\n\nAfter | text\n"
    header, rows = lab01.first_table(body)
    assert header == ["ID", "Component", "STRIDE", "Threat", "Mitigation", "Status"]
    assert rows == [["T1", "c", "Spoofing", "t", "m", "Built"]]


def test_first_table_keeps_escaped_pipes_in_a_cell(lab01):
    _, rows = lab01.first_table(HEADER + r"| T1 | a \| b | Spoofing | t | m | Built |" + "\n")
    assert rows[0][1] == "a | b"


def test_first_table_accepts_aligned_separators_and_no_outer_pipes(lab01):
    body = "| A | B |\n|:---|---:|\n| 1 | 2 |\n"
    assert lab01.first_table(body) == (["A", "B"], [["1", "2"]])


@pytest.mark.parametrize("body", [
    "no table here",
    "| A | B |\n| 1 | 2 |\n",
    "| A | B |\nnot a separator\n",
])
def test_first_table_needs_a_separator_row(lab01, body):
    assert lab01.first_table(body) is None


def test_short_rows_get_empty_cells(lab01):
    assert lab01.rows_as_dicts(["A", "B", "C"], [["1"]]) == [{"A": "1", "B": "", "C": ""}]


def test_stride_categories_reads_several_and_ignores_case(lab01):
    found = lab01.stride_categories("tampering; Elevation of Privilege")
    assert found == {"Tampering", "Elevation of privilege"}


def test_reference_threat_model_passes_every_check(lab01, monkeypatch):
    monkeypatch.setattr(lab01, "THREAT_MODEL", REFERENCE)
    for check in checks(lab01):
        check()


@pytest.mark.parametrize("name", [
    "test_data_flow_diagram_is_a_code_block",
    "test_enough_threats",
    "test_stride_covered",
    "test_prompt_injection_considered",
])
def test_skeleton_fails(lab01, monkeypatch, name):
    monkeypatch.setattr(lab01, "THREAT_MODEL", SKELETON)
    with pytest.raises(AssertionError):
        getattr(lab01, name)()


def test_skeleton_has_the_headings_and_columns(lab01, monkeypatch):
    monkeypatch.setattr(lab01, "THREAT_MODEL", SKELETON)
    lab01.test_headings_present()
    assert lab01.threat_rows() == []


def test_missing_file_fails_every_check_with_a_message(lab01, monkeypatch, tmp_path):
    use(lab01, monkeypatch, tmp_path, None)
    for check in checks(lab01):
        with pytest.raises(AssertionError, match="create docs/threat-model.md"):
            check()


def test_missing_headings_are_named(lab01, monkeypatch, tmp_path):
    use(lab01, monkeypatch, tmp_path, "## Assets\nx\n")
    with pytest.raises(AssertionError, match="'## System overview'.*'## Top risks'"):
        lab01.test_headings_present()


def test_missing_threats_section_is_reported(lab01, monkeypatch, tmp_path):
    use(lab01, monkeypatch, tmp_path, "## Assets\nx\n")
    with pytest.raises(AssertionError, match="no '## Threats' heading"):
        lab01.test_enough_threats()


def test_missing_table_is_reported(lab01, monkeypatch, tmp_path):
    use(lab01, monkeypatch, tmp_path, "## Threats\nprose only\n")
    with pytest.raises(AssertionError, match="no Markdown table"):
        lab01.test_enough_threats()


def test_missing_columns_are_named(lab01, monkeypatch, tmp_path):
    text = "## Threats\n| ID | Threat |\n|---|---|\n| T1 | x |\n"
    use(lab01, monkeypatch, tmp_path, text)
    with pytest.raises(AssertionError, match="Component, STRIDE, Mitigation, Status"):
        lab01.test_every_row_complete()


def test_empty_cells_are_named_by_row(lab01, monkeypatch, tmp_path):
    text = "## Threats\n" + HEADER + "| T1 | c | Spoofing | t |  | Built |\n| | c | Spoofing |\n"
    use(lab01, monkeypatch, tmp_path, text)
    with pytest.raises(AssertionError) as failure:
        lab01.test_every_row_complete()
    message = str(failure.value)
    assert "T1: empty Mitigation" in message
    assert "data row 2: empty ID, Threat, Mitigation, Status" in message


def test_too_few_rows_reports_the_count(lab01, monkeypatch, tmp_path):
    text = "## Threats\n" + HEADER + "| T1 | c | Spoofing | t | m | Built |\n"
    use(lab01, monkeypatch, tmp_path, text)
    with pytest.raises(AssertionError, match="has 1 data row"):
        lab01.test_enough_threats()


def test_uncovered_stride_categories_are_named(lab01, monkeypatch, tmp_path):
    text = "## Threats\n" + HEADER + "| T1 | c | Spoofing, Tampering | t | m | Built |\n"
    use(lab01, monkeypatch, tmp_path, text)
    with pytest.raises(AssertionError) as failure:
        lab01.test_stride_covered()
    message = str(failure.value)
    assert "Repudiation, Information disclosure, Denial of service, Elevation" in message
    assert "Spoofing" not in message.split(".")[0]


@pytest.mark.parametrize(("threat", "passes"), [
    ("Prompt injection in a docstring", True),
    ("indirect prompt-injection via a test fixture", True),
    ("a prompt that is long", False),
])
def test_prompt_injection_match(lab01, monkeypatch, tmp_path, threat, passes):
    text = "## Threats\n" + HEADER + f"| T1 | c | Tampering | {threat} | m | Built |\n"
    use(lab01, monkeypatch, tmp_path, text)
    if passes:
        lab01.test_prompt_injection_considered()
    else:
        with pytest.raises(AssertionError, match="prompt injection"):
            lab01.test_prompt_injection_considered()


def test_todo_cells_are_named(lab01, monkeypatch, tmp_path):
    text = "## Threats\n" + HEADER + "| T1 | c | Spoofing | t | TODO | Built |\n"
    use(lab01, monkeypatch, tmp_path, text)
    with pytest.raises(AssertionError, match=r"T1 \(Mitigation\)"):
        lab01.test_no_todo_cells()
