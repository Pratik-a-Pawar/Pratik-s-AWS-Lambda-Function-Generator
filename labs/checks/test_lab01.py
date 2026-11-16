"""Lab 01 acceptance checks: the shape of docs/threat-model.md.

Run with `lfg labcheck 01`. These checks confirm the document is complete enough to review;
they cannot judge whether the threats are the right ones. That is the debrief's job.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
HEADINGS = [
    "System overview", "Data flow diagram", "Assets", "Trust boundaries", "Threats", "Top risks",
]
COLUMNS = ["ID", "Component", "STRIDE", "Threat", "Mitigation", "Status"]
STRIDE = [
    "Spoofing", "Tampering", "Repudiation", "Information disclosure", "Denial of service",
    "Elevation of privilege",
]
MIN_THREATS = 15

LEVEL_1_OR_2_HEADING = re.compile(r"^(#{1,2})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
SEPARATOR_CELL = re.compile(r"^:?-+:?$")
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
PROMPT_INJECTION = re.compile(r"prompt[\s-]+injection", re.IGNORECASE)


def sections(text: str) -> dict[str, str]:
    """Map each level 2 heading's title to the text under it, ignoring fenced code."""
    found: dict[str, list[str]] = {}
    current = None
    in_fence = False
    for line in text.splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and (match := LEVEL_1_OR_2_HEADING.match(line)):
            current = match.group(2) if match.group(1) == "##" else None
            if current:
                found.setdefault(current, [])
            continue
        if current:
            found[current].append(line)
    return {title: "\n".join(lines) for title, lines in found.items()}


def has_fenced_block(body: str) -> bool:
    """True when the text holds an opening fence with a matching closing fence."""
    fences = [line for line in body.splitlines() if FENCE.match(line)]
    return len(fences) >= 2


def _cells(line: str) -> list[str]:
    inner = line.strip()
    inner = inner.removeprefix("|")
    inner = inner[:-1] if inner.endswith("|") and not inner.endswith("\\|") else inner
    return [cell.strip().replace("\\|", "|") for cell in UNESCAPED_PIPE.split(inner)]


def first_table(body: str) -> tuple[list[str], list[list[str]]] | None:
    """Return (header, data rows) of the first Markdown table in the text, or None."""
    lines = body.splitlines()
    for index in range(len(lines) - 1):
        if not lines[index].lstrip().startswith("|"):
            continue
        separator = _cells(lines[index + 1])
        if not lines[index + 1].lstrip().startswith("|") or not all(
            SEPARATOR_CELL.match(cell) for cell in separator
        ):
            continue
        rows = []
        for line in lines[index + 2:]:
            if not line.lstrip().startswith("|"):
                break
            rows.append(_cells(line))
        return _cells(lines[index]), rows
    return None


def rows_as_dicts(header: list[str], rows: list[list[str]]) -> list[dict[str, str]]:
    """Key each row's cells by column name; a short row has empty cells at the end."""
    names = [name.strip() for name in header]
    return [
        {name: (row[position] if position < len(row) else "") for position, name in enumerate(names)}
        for row in rows
    ]


def stride_categories(cell: str) -> set[str]:
    """The STRIDE categories named in one cell."""
    lowered = cell.lower()
    return {category for category in STRIDE if category.lower() in lowered}


def read_threat_model() -> str:
    relative = THREAT_MODEL.relative_to(ROOT)
    assert THREAT_MODEL.is_file(), (
        f"create {relative}: start from the skeleton described in labs/01-threat-model/README.md"
    )
    try:
        return THREAT_MODEL.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AssertionError(f"cannot read {relative} as UTF-8 text: {exc}") from None


def threat_rows() -> list[dict[str, str]]:
    threats = sections(read_threat_model()).get("Threats")
    assert threats is not None, "there is no '## Threats' heading"
    table = first_table(threats)
    assert table is not None, (
        "the '## Threats' section has no Markdown table (a header row, then a |---| row)"
    )
    header, rows = table
    missing = [column for column in COLUMNS if column not in header]
    assert not missing, (
        f"the threats table is missing the column(s) {', '.join(missing)};"
        f" the header must include {' | '.join(COLUMNS)}"
    )
    return rows_as_dicts(header, rows)


def test_headings_present():
    found = sections(read_threat_model())
    missing = [heading for heading in HEADINGS if heading not in found]
    assert not missing, "add the heading(s): " + ", ".join(f"'## {h}'" for h in missing)


def test_data_flow_diagram_is_a_code_block():
    body = sections(read_threat_model()).get("Data flow diagram")
    assert body is not None, "there is no '## Data flow diagram' heading"
    assert has_fenced_block(body), (
        "draw the data flow diagram inside a fenced code block (``` ... ```)"
        " under '## Data flow diagram'"
    )


def test_enough_threats():
    rows = threat_rows()
    assert len(rows) >= MIN_THREATS, (
        f"the threats table has {len(rows)} data row(s); write at least {MIN_THREATS}"
    )


def test_every_row_complete():
    gaps = []
    for number, row in enumerate(threat_rows(), start=1):
        empty = [column for column in COLUMNS if not row[column]]
        if empty:
            label = row["ID"] or f"data row {number}"
            gaps.append(f"{label}: empty {', '.join(empty)}")
    assert not gaps, "fill in every column of every threat:\n- " + "\n- ".join(gaps)


def test_stride_covered():
    covered = set().union(*(stride_categories(row["STRIDE"]) for row in threat_rows()))
    missing = [category for category in STRIDE if category not in covered]
    assert not missing, (
        "no threat is classified as: " + ", ".join(missing)
        + ". Write the category names in full in the STRIDE column"
    )


def test_prompt_injection_considered():
    assert any(PROMPT_INJECTION.search(row["Threat"]) for row in threat_rows()), (
        "no threat mentions prompt injection; the AI reviewers read files an attacker can write"
    )


def test_no_todo_cells():
    todo = [
        f"{row['ID'] or 'a row'} ({column})"
        for row in threat_rows() for column, cell in row.items() if "TODO" in cell
    ]
    assert not todo, "replace TODO in: " + ", ".join(todo)
