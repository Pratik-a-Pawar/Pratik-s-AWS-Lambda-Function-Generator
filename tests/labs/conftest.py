import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    path = ROOT / "labs" / "checks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"labcheck_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def lab00():
    return _load("test_lab00")


@pytest.fixture
def lab01():
    return _load("test_lab01")
