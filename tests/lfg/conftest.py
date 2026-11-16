import shutil
from pathlib import Path

import pytest
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
