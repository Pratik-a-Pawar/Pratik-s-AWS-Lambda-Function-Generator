import shutil
from pathlib import Path

import pytest
from lfg.cfn_yaml import load_template
from lfg.spec import load_spec

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def good_dir(tmp_path: Path) -> Path:
    target = tmp_path / "good"
    shutil.copytree(FIXTURES / "good", target)
    return target


@pytest.fixture
def good_spec(good_dir: Path) -> dict:
    return load_spec(good_dir / "function.spec.yaml")


@pytest.fixture
def good_template(good_dir: Path) -> dict:
    return load_template(good_dir / "template.yaml")


def rule_ids(violations) -> set[str]:
    """IDs of the violations that still block (not accepted)."""
    return {v.rule_id for v in violations if not v.accepted}
