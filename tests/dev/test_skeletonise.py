import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "tools" / "dev" / "skeletonise.py"
_SPEC = importlib.util.spec_from_file_location("skeletonise", _PATH)
skeletonise = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(skeletonise)


def make_repo(tmp_path: Path, owned: list[str], skeletons: dict[str, str]) -> Path:
    (tmp_path / "labs").mkdir()
    lines = "\n".join(f"      - {o}" for o in owned) or "      []"
    owned_yaml = f"\n{lines}" if owned else f" {lines.strip()}"
    (tmp_path / "labs" / "manifest.yaml").write_text(
        'labs:\n  "01":\n    title: One\n    dir: labs/01\n'
        f"    owned:{owned_yaml}\n    checks: []\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "real.py").write_text("real\n", encoding="utf-8")
    (tmp_path / "tools" / "other.py").write_text("other\n", encoding="utf-8")
    for name, content in skeletons.items():
        path = tmp_path / "labs" / "01" / "skeleton" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def test_owned_file_is_replaced_by_skeleton(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    assert skeletonise.apply(root) == [root / "tools" / "real.py"]
    assert (root / "tools" / "real.py").read_text() == "skeleton\n"


def test_skeleton_directory_is_removed(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    skeletonise.apply(root)
    assert not (root / "labs" / "01" / "skeleton").exists()


def test_unowned_file_is_unchanged(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    skeletonise.apply(root)
    assert (root / "tools" / "other.py").read_text() == "other\n"


def test_missing_skeleton_raises_and_changes_nothing(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py", "tools/other.py"], {"tools/real.py": "skeleton\n"})
    with pytest.raises(FileNotFoundError, match="tools/other.py"):
        skeletonise.apply(root)
    assert (root / "tools" / "real.py").read_text() == "real\n"
    assert (root / "labs" / "01" / "skeleton").is_dir()


@pytest.mark.parametrize("owned", ["../escape.py", "tools/../../escape.py", "/etc/escape.py"])
def test_escaping_path_raises_and_changes_nothing(tmp_path, owned):
    root = make_repo(tmp_path, [owned], {})
    with pytest.raises(ValueError, match="escape"):
        skeletonise.apply(root)
    assert (root / "tools" / "real.py").read_text() == "real\n"
